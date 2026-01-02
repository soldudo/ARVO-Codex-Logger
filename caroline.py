import logging
import subprocess
import json
import os
import shutil
import sys
import time
from datetime import datetime
from collections import deque
from pathlib import Path
from queries import get_context
from arvo_tools import initial_setup, standby_container, docker_copy
from commit_files import download_commit_files

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caroline.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Hard coded experiment parameters (informational)
vuln_list = [40096184, 42488087, 42513136, 42530547, 424242614]
project_list = ['skia', 'wolfssl', 'binutils-preconditions', 'opensc', 'libxml2']
fuzz_target = [
    './out/android_codec tmp/poc', # 40096184
    './out/fuzzer-wolfssl-server-randomize tmp/poc', # 42488087
    './out/fuzz_objdump_safe tmp/poc', # 42513136
    './out/fuzz_pkcs11 tmp/poc', # 42530547
    './out/schema tmp/poc' # 424242614
]
crash_type_list = [
    'Heap-buffer-overflow WRITE 4',
    'Heap-buffer-overflow WRITE 1', # 42488087
    'Heap-double-free', # 42513136
    'Stack-buffer-overflow READ 8', # 42530547
    'Heap-buffer-overflow WRITE 1' # 424242614
]
experiment_no = 1  # Change this index to run different experiments
project = project_list[experiment_no]
crash_type = crash_type_list[experiment_no]
# workspace_list = [
#     '',
#     f'{vuln}/src/wolfssl', # 42488087
#     f'{vuln}/src/binutils-preconditions', # 42513136
#     f'{vuln}/src/opensc', # 42530547
#     'arvo-424242614-vul-1766980840/src/libxml2' # 424242614
# ]

def load_config():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'experiment_setup.json')

    if not os.path.exists(config_path):
        logger.critical(f"Config file not found at {config_path}")
        print(f"CRITICAL: Config file not found at {config_path}")
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            data = json.load(f)
            logger.info(f'loaded experiment parameters: {data}')
            return data
            
    except json.JSONDecodeError as e:
        logger.critical(f"JSON file is corrupt or invalid: {e}")
        print(f"CRITICAL: JSON file is corrupt or invalid.\nError details: {e}")
        sys.exit(1)

def conduct_run(vuln_id: str, container: str, prompt: str, workspace: Path, patch_url: str = None):
    run_timestamp = int(time.time())
    log_path = Path(__file__).parent / "runs" / container / f"agent-{container}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    command = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), prompt]
    
    # command_initial = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), prompt]
    # command_retry_last = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), 'resume', '--last', prompt]
    # command_retry_resume_id = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), 'resume', '019b3597-268f-7c90-9a60-fb713ee6104f', prompt]

    print("using command:", command)
    print(f'Logging to {log_path}\n')
    
    start_time = time.time()
    duration = 0.0
    return_code = None
    modified_files = []
    modified_files_relative = []

    logger.info(f'logging codex run to {log_path}')

    with open(log_path, 'w', encoding='utf-8') as log_file:
        meta_start = {
            'log_type': 'session_start',
            'timestamp_iso': datetime.now().isoformat(),
            'timestamp_unix': start_time,
            'vuln': vuln_id,
            'patch_url': patch_url,
            'workspace': str(workspace),
            'command': command[:-1],
            'prompt': prompt
        }

        log_file.write(json.dumps(meta_start) + '\n')
        log_file.flush()
        logger.info(f'Beginning Codex execution for {container}')

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        try:
            for line in process.stdout:
                line = line.rstrip('\n')
                if not line.strip():
                    continue

                log_entry = {
                    'log_type': 'stream_output',
                    'timestamp_iso': datetime.now().isoformat(),
                    'timestamp_unix': time.time(),
                    'data': None
                }

                try:
                    event = json.loads(line)
                    log_entry['data'] = event
                    msg_type = event.get('type')

                    # Case 1: Command Execution Result
                    if msg_type == 'item.completed' and event.get('item', {}).get('type') == 'command_execution':
                        item = event['item']
                        raw_output = item.get('aggregated_output', '')
                        exit_code = item.get('exit_code')
                        print(f"\n[Command Result - Exit {exit_code}]:\n{raw_output}")

                    # Case 2: Reasoning (Thinking)
                    elif msg_type == 'item.completed' and event.get('item', {}).get('type') == 'reasoning':
                        text = event['item'].get('text', '').replace('**', '')
                        print(f"\n[Thinking]: {text}")
                    
                    # Case 3: Executing Command
                    elif msg_type == 'item.started' and event.get('item', {}).get('type') == 'command_execution':
                        print(f"\n> [Executing]: {event['item'].get('command')}")

                    # Case 4: Final Message
                    elif msg_type == 'item.completed' and event.get('item', {}).get('type') =='agent_message':
                        text = event['item'].get('text', '')
                        print(f"\n[agent_message]: {text}")

                except json.JSONDecodeError:
                    print(f'Non-JSON output: {line}')
                    log_entry['data'] = {'raw_text': line}
                    continue
                
                log_file.write(json.dumps(log_entry) + '\n')
                log_file.flush()
                
            return_code = process.wait()
            end_time = time.time()
            duration = end_time - start_time

            logger.info(f'Codex run completed with return code {return_code} in {duration:.8f} seconds.')

            # get files modified by agent
            try:
                find_result = subprocess.run([
                    'find', str(workspace), # search agent's workspace
                    '-type', 'f',
                    '-not', '-path', '*/.git/*', # ignore .git files
                    '-newermt', f'@{start_time}', # files modified since run's start_time
                    '-printf', '%T@ %p\n'
                ],
                capture_output=True, text=True, check=False)
                if find_result.stdout:
                    logger.info("Files modified by agent:")
                    for line in find_result.stdout.splitlines():
                        logger.info(line)
                        parts = line.split(' ', 1)
                        if len(parts) == 2:
                            time_str, mod_filepath = parts # time_str can be used to verify mod time
                            modified_files.append(mod_filepath)

                print(f'Modified files since start of run: {modified_files}')
            except Exception as e:
                print(f'Error finding modified files: {e}')

            stderr_output = process.stderr.read()
            if stderr_output:
                print('\nCodex stderr output:\n', stderr_output)
                log_file.write(json.dumps({
                    'log_type': 'stderr_output',
                    'timestamp_iso': datetime.now().isoformat(),
                    'timestamp_unix': time.time(),
                    'data': stderr_output
                }) + '\n')
                # log_file.flush() # copilot rec
            
            print(f'Codex finished with return code {return_code} in {duration:.2f} seconds.')

        except Exception as e:
            logger.error(f'Error during Codex execution: {e}')
            print(f'Error during execution: {e}')
            log_file.write(json.dumps({
                'log_type': 'execution_error',
                'timestamp_iso': datetime.now().isoformat(),
                'timestamp_unix': time.time(),
                'data': str(e)
            }) + '\n')
            raise e
                
        finally:
            for file in modified_files:
                try:
                    relative_path = Path(file).relative_to(workspace)
                    modified_files_relative.append(str(relative_path))
                except ValueError:
                    modified_files_relative.append(file)  # fallback to full path if relative fails

            meta_end = {
                'log_type': 'session_end',
                'timestamp_iso': datetime.now().isoformat(),
                'timestamp_unix': time.time(),
                'duration_seconds': duration,
                'return_code': return_code,
                'modified_files': modified_files_relative    
            }
            log_file.write(json.dumps(meta_end) + '\n')
            log_file.close()
            logger.info(f'Codex run log saved to {log_path}')
    
    return modified_files

if __name__ == "__main__":
    patch_url = None
    experiment_params = load_config()
    vuln_id = experiment_params.get('arvo_id')
    initial_prompt = experiment_params.get('initial_prompt')

    # Get project and crash type from ARVO.db
    logger.info(f'Fetching context for arvo {vuln_id}')
    project, crash_type, patch_url = get_context(vuln_id)
    logger.info(f"Experiment setup for ARVO ID {vuln_id}: project={project}, crash_type={crash_type}, patch_url={patch_url}")
    # Does not check for patch url which isn't critical to execution
    if project is None or crash_type is None: 
        context_error = f"ERROR: Missing context - project is {project} and crash_type is {crash_type} for ID {vuln_id}. Execution aborted."
        logger.error(context_error)
        raise ValueError(context_error)

    # Use experiment_setup.json to indicate if this is an initial prompt
    if initial_prompt:
        logger.info("Using initial prompt for experiment.")
        prompt = f'Find and fix the bug in {project} to remove the {crash_type} shown in the log below. Provide the lines of code and file locations changed in this task.'

        logger.info(f'Generating original arvo crash log and extracting filesystem.')
        container, crash_original = initial_setup(vuln_id)

        crash_path = Path(__file__).parent / crash_original
        logger.info(f'Reading crash log from {crash_path}')
        try:
            with open(crash_path, "r", encoding="utf-8", errors="replace") as f:
                crash_log = f.read()
        except FileNotFoundError:
            logger.error(f"Error: The file {crash_path} was not found.")

        prompt += f'<crash_log>{crash_log}</crash_log>'

        workspace = Path(__file__).parent / container / 'src' / project

        # assign list of modified files to var for automated archiving and retrieval of originals
        # extend to calling container's arvo compile and arvo
        modified_files = conduct_run(vuln_id, container, prompt, workspace, patch_url)

        run_path = Path(__file__).parent / 'runs' / container

        # copy crash log to run folder for archiving
        shutil.copy2(crash_path, run_path)

        # download ground truth from repo commit url
        try:
            logger.info(f'Downloading commit files from {patch_url} to {run_path}')
            download_commit_files(patch_url, run_path)
        except Exception as e:
            logger.error(f'Skipping download. Error getting commit files from {patch_url}: {e}')

        
        # copy modified files to experiment run folder for archiving
        for mod_file in modified_files:
            mod_filepath = Path(mod_file)
            if mod_filepath.exists():
                try:
                    relative_path = mod_filepath.relative_to(workspace)
                    # TODO: verify the next line's behavior is as intended
                    flat_name = str(relative_path).replace('/', '__').replace('\\', '__')
                    new_name = f'{flat_name}-patch1' # WARNING: inside first attempt block. Adjust if refactored
                    dest_path = run_path / new_name
                    shutil.copy2(mod_filepath, dest_path)
                    logger.info(f'Copied modified file {mod_filepath} to {dest_path}')
                except Exception as e:
                    logger.error(f'Error copying modified file {mod_filepath}: {e}')
        
        # must truncate local path for container compatibility
        base_to_remove = workspace.parents[1]
        
        # run container indefinitely and extract original copies of modified files
        try:
            standby_container(vuln_id, container)

            for mod_file in modified_files:
                mod_filepath = Path(mod_file)
                filename = mod_filepath.name
                relative_path = mod_filepath.relative_to(base_to_remove)

                logger.info(f'docker copy original file {relative_path} to {run_path}/{filename}-original')
                docker_copy(container, str(relative_path), run_path, container_source_flag=True)

        except Exception as e:
            logger.error(f'Error docker copying original files: {e}')

        # copy the modified files into the container
        for mod_file in modified_files:
            mod_filepath = Path(mod_file)
            filename = mod_filepath.name
            relative_path = mod_filepath.relative_to(base_to_remove)

            logger.info(f'docker copy modified file {mod_filepath} to container at {relative_path}')
            docker_copy(container, str(mod_filepath), str(relative_path), container_source_flag=False)


        # re-compile
        KEEP_LINES = 20
        compile_cmd = ['docker', 'exec', container, 'arvo', 'compile']
        logger.info(f'Re-compiling {container}')
        try:
            with subprocess.Popen(compile_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1) as proc:
                last_lines = deque(maxlen=KEEP_LINES)
                for line in proc.stdout:
                    last_lines.append(line)
            
            compile_log = ''.join(last_lines)
            if proc.returncode == 0:
                logger.info(f'Container {container} re-compiled successfully.\n'
                            
                            f'--- Last {KEEP_LINES} lines of output ---\n'
                            f'{compile_log}')
            else:
                logger.error(f'Container {container} failed to re-compile with exit code {proc.returncode}.\n' 
                            f'--- Last {KEEP_LINES} lines of output ---\n'
                            f'{compile_log}')
        except Exception as e:
            logger.exception(f'Error during re-compilation of container {container}: {e}')
        # TODO : Explore how much we need to verify compile success
        # Will compile failure automatically result in re-fuzz crash?

        # re-run poc and capture new crash/success log
        fuzz_cmd = ['docker', 'exec', container, 'arvo']
        logger.info(f'Re-running arvo poc on {container}')
        fuzz_result = subprocess.run(fuzz_cmd, capture_output=True, text=True)
        crash_log_path = run_path / 'crash_first_patch.log'
        logger.info(f'Writing first patch crash log to {crash_log_path}')
        logger.info(f'arvo (re-run poc) stdout:\n{fuzz_result.stdout}')
        logger.info(f'arvo (re-run poc) stderr:\n{fuzz_result.stderr}')
        with open(crash_log_path, 'w', encoding='utf-8', errors='replace') as f:
            f.write('--- STDOUT ---\n')
            f.write(fuzz_result.stdout)
            if fuzz_result.stderr:
                f.write('\n--- STDERR ---\n')
                f.write(fuzz_result.stderr)

    # crash_first_patch = Path(__file__).parent / 'runs' / container / 'crash_first_patch.log'
    # crash_path = Path(__file__).parent / 'runs' / container / 'crash_first_patch.log'

    # try:
    #     with open(crash_path, "r", encoding="utf-8", errors="replace") as f:
    #         crash_log = f.read()
    # except FileNotFoundError:
    #     print(f"Error: The file {crash_path} was not found.")

    # prompt = 'Your previous fixes did not remove the crash as indicated by this new crash log:'
    # prompt += f'<crash_log>{crash_log}</crash_log>'
    # prompt += 'The workspace has been reset with the original files. A known correct fix made changes to the following files:' 
    # prompt += 'src/internal.c around lines 21167 - 21171, 23224, 25164 and 25176; wolfcrypt/src/dh.c near lines 1212, 1244, 1284 and 1289; and wolfcrypt/test/test.c near lines 14644, 14766 and 14812.' 
    # prompt += 'Use this information to reattempt the fix.'

    # # prompt = f'Find and fix the bug in {project} to remove the {crash_type} shown in the log below. Provide the lines of code and file locations changed in this task.'
    
    # conduct_run(vuln_list[experiment_no], container, prompt, workspace)
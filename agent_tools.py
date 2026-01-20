from datetime import datetime
import json
import logging
from pathlib import Path
from queries import init_db, record_run
from schema import RunRecord
import subprocess
import time

logger = logging.getLogger(__name__)

def get_model():
    agent_model = None
    command = ['codex', 'exec', '/status']
    try:
            
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{' '.join(command)}' failed with return code {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
    for line in result.stderr.splitlines():
        if line.strip().startswith('model:'):
            agent_model = line.strip().split('model:')[1].strip()
            logger.info(f'Agent model detected: {agent_model}')

    return agent_model

# resume_flag = True when instructing agent to resume last or specified session
# if flag is true, but id is none, last will be used
def conduct_run(vuln_id: str, container: str, prompt: str, workspace: Path, agent: str, resume_flag: bool = False, resume_session_id: str =None, patch_url: str = None):

    agent_model = get_model()

    # first attempt
    if not resume_flag:
        command = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), prompt]
        log_path = Path(__file__).parent / "runs" / container / f"agent_{container}.log"


    # second attempt on 1) last session or 2) specified session
    else:
        log_path = Path(__file__).parent / "runs" / container / f"agent_{container}_patch2.log"
        if not resume_session_id:
            command = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), 'resume', '--last', prompt]
        else:
            command = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), 'resume', resume_session_id, prompt]

    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f'Logging to {log_path}\n')
    logger.info(f"Invoking agent with: {command}")
    
    start_time = time.time()
    duration = 0.0
    return_code = None
    modified_files = []
    modified_files_relative = []
    workspace_relative = workspace.relative_to(workspace.parents[1])

    with open(log_path, 'w', encoding='utf-8') as log_file:
        meta_start = {
            'log_type': 'session_start',
            'timestamp_iso': datetime.now().isoformat(),
            'timestamp_unix': start_time,
            'vuln': vuln_id,
            'patch_url': patch_url,
            'workspace': str(workspace_relative),
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
                        print(f"\n[agent_exe_result - Exit {exit_code}]:\n{raw_output}")

                    # Case 2: Reasoning (Thinking)
                    elif msg_type == 'item.completed' and event.get('item', {}).get('type') == 'reasoning':
                        text = event['item'].get('text', '').replace('**', '')
                        print(f"\n[agent_reasoning]: {text}")
                    
                    # Case 3: Executing Command
                    elif msg_type == 'item.started' and event.get('item', {}).get('type') == 'command_execution':
                        print(f"\n> [agent_executing]: {event['item'].get('command')}")

                    # Case 4: Final Message
                    elif msg_type == 'item.completed' and event.get('item', {}).get('type') =='agent_message':
                        text = event['item'].get('text', '')
                        print(f"\n[agent_message]: {text}")
                        agent_reasoning = text  

                    # agent session id - parameter for resume
                    elif msg_type ==  'thread.started':
                        thread_id = event.get('thread_id')
                        print(f"\n[agent_session_id]: {thread_id}")

                    # token usage
                    elif msg_type == 'turn.completed':
                        usage = event.get('usage')
                        input_tokens = usage.get('input_tokens') 
                        cached_input_tokens = usage.get('cached_input_tokens')
                        output_tokens = usage.get('output_tokens')
                        # input tokens should include cached_input_tokens
                        total_tokens = input_tokens + output_tokens 

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

                logger.info(f'Modified files since start of run: {modified_files}')
            except Exception as e:
                logger.error(f'Error finding modified files: {e}')

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
            run_root = workspace.parents[1]
            for file in modified_files:
                try:
                    relative_path = Path(file).relative_to(run_root)
                    truncated_path = Path(*relative_path.parts[2:])  # remove 'src' and project folder for container path
                    logger.info(f'Relative modified file path: {relative_path} was file: {file} relative to workspace {workspace}')
                    logger.info(f'Truncated modified file path for db: {truncated_path}')
                    modified_files_relative.append(str(truncated_path))
                except ValueError:
                    modified_files_relative.append(file)  # fallback to full path if relative fails

            # run metrics
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

            try:
                with open(log_path, 'r', encoding='utf-8') as f_read:
                    agent_log = f_read.read()

            except Exception as e:
                logger.error(f'Error reading agent log for db storage: {e}')
                agent_log = ''

            # initialize runs table
            init_db()

            # DTO
            run_data = RunRecord(
                run_id=container,
                vuln_id=vuln_id,
                workspace_relative=str(workspace_relative),
                patch_url=patch_url,
                prompt=prompt,
                duration=duration,
                input_tokens=input_tokens,
                cached_input_tokens=cached_input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                agent=agent,
                agent_model=agent_model,
                resume_flag=resume_flag,
                resume_id=thread_id,
                agent_log=agent_log,
                agent_reasoning=agent_reasoning,
                modified_files_relative=modified_files_relative
            )

            # insert run record into db
            record_run(run_data)
            logger.info(f'Recorded run in database with ID {container}')
    
    return modified_files, modified_files_relative
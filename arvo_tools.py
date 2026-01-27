from collections import deque
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from queries import get_context

logger = logging.getLogger(__name__)

def setup_logger():
    # logger for development debugging. This does not capture LLM info
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("arvo-tools.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def run_command(cmd, check=True, stdout=None, stderr=subprocess.PIPE, timeout=None):
    try:
        logger.debug(f'Executing: {" ".join(cmd)}')
        result = subprocess.run(
            cmd,
            stdout=stdout,
            stderr=stderr,
            text=True,
            timeout=timeout,
            check=check
        )
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f'Command failed with exit code: {e.returncode}')
        logger.error(f'Stderr: {e.stderr}')
        raise
    except subprocess.TimeoutExpired as e:
        logger.error(f'Command timed out: {e}')
        raise

def make_fs(container_name: str):
    fs_dir = os.path.join(os.getcwd(), 'scratch_fs', container_name)
    os.makedirs(fs_dir, exist_ok=True)
    return fs_dir

# change fix_flag to 'fix' to load the patched container
def load_container(arvo_id: int, fix_flag: str = 'vul'):
    # pull container first for concise crash_log
    pull_call = ['docker', 'pull', f'n132/arvo:{arvo_id}-{fix_flag}']
    logger.debug(f"Pulling image n132/arvo:{arvo_id}-{fix_flag}")
    run_command(pull_call)

    container_name = f'arvo-{arvo_id}-{fix_flag}-{int(time.time())}'
    container_call = ['docker', 'run',
                      '--name', container_name,
                      '-i', f'n132/arvo:{arvo_id}-{fix_flag}', 'arvo'
    ]
    log_file = f'crash_{container_name}.log'
    logger.info(f"Starting container {container_name}, logging to {log_file}")

    with open(log_file, 'w', encoding='utf-8', errors='replace') as crash_log:
        run_command(container_call, stdout=crash_log, stderr=subprocess.STDOUT, check=False)
        
    return container_name, log_file

def export_container(container_name, fs_dir):
    output_tar = f'{container_name}.tar'
    output_path = os.path.join(fs_dir, output_tar)
    logger.debug(f"Exporting container {container_name} tar to {output_path}")
    cmd = ['docker', 'export', container_name, '-o', output_path]
    run_command(cmd)

    if not os.path.exists(output_path):
        logger.error(f"Failed to export container {container_name} to {output_path}")
        raise FileNotFoundError(f"{output_path} not found after export")
    
    return output_path

def extract_files(container_tar: str, fs_dir):
    logger.debug(f"Extracting {container_tar} to {fs_dir}")
    
    cmd = ['tar', '-xf', container_tar, '-C', fs_dir]
    result = run_command(cmd, check=False)

    if result.returncode != 0:
        logger.warning(f"Process finished with abnormal exit code {result.returncode} for {container_tar}. Please manually verify project directory files are intact!")

    # this check needs to be updated to verify extraction success while ignoring .tar
    # if not any(os.scandir(container_name)):
    #     logger.error(f"No files found in extracted directory {container_name}")
    #     raise FileNotFoundError(f"No files extracted to {container_name}")

def cleanup_tar(tar_path: str):
    if os.path.exists(tar_path):
        logger.debug(f"Removing tar file {tar_path}")
        os.remove(tar_path)
    else:
        logger.warning(f"Tar file {tar_path} does not exist for cleanup")

def cleanup_container(container_name: str):
    logger.debug(f"Cleaning up container {container_name}")
    cmd = ['docker', 'rm', '-f', container_name]
    run_command(cmd, check=False)

def standby_container(container_name: str, vuln_id: int, fix_flag: str = 'vul'):
    stby_cmd = ['docker', 'run', '-d',
                 '--name', container_name,
                 '--entrypoint', 'tail',
                 f'n132/arvo:{vuln_id}-{fix_flag}',
                 '-f', '/dev/null'
    ]
    logger.debug(f"Starting standby container {container_name}")
    run_command(stby_cmd)

def recompile_container(container_name: str):
    KEEP_LINES = 20
    compile_cmd = ['docker', 'exec', container_name, 'arvo', 'compile']
    logger.info(f'Re-compiling {container_name}')
    try:
        with subprocess.Popen(compile_cmd,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1) as proc:
            last_lines = deque(maxlen=KEEP_LINES)
            for line in proc.stdout:
                last_lines.append(line)
        
        compile_log = ''.join(last_lines)

        # TODO: recompiling failure can still prodoce this successful recomiplation msg
        if proc.returncode == 0:
            logger.info(f'Container {container_name} re-compiled successfully.\n'
                        
                        f'--- Last {KEEP_LINES} lines of output ---\n'
                        f'{compile_log}')
        else:
            logger.error(f'Container {container_name} failed to re-compile with exit code {proc.returncode}.\n' 
                        f'--- Last {KEEP_LINES} lines of output ---\n'
                        f'{compile_log}')
    except Exception as e:
        logger.exception(f'Error during re-compilation of container {container_name}: {e}')

# helper function to move files in and out of docker containers
def docker_copy(container_name: str, src_path: str, dest_path: str, container_source_flag: bool):
    if container_source_flag:
        copy_cmd = ['docker', 'cp', f'{container_name}:{src_path}', f'{dest_path}']
    else:
        copy_cmd = ['docker', 'cp', src_path, f'{container_name}:{dest_path}']
    
    logger.info(f"Copying {'from' if container_source_flag else 'to'} container {container_name}: {src_path} -> {dest_path}")
    run_command(copy_cmd)

def refuzz(container_name):
    fuzz_cmd = ['docker', 'exec', container_name, 'arvo']
    logger.info(f'Re-running arvo poc on {container_name}')
    fuzz_result = run_command(
        fuzz_cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60) # Should be quick, might wanna lower

    return fuzz_result

def initial_setup(arvo_id: int, fix_flag: str = 'vul'):
    container, log_file = load_container(arvo_id, fix_flag)
    fs_dir = make_fs(container)
    exported_tar = export_container(container, fs_dir)
    extract_files(exported_tar, fs_dir)
    cleanup_tar(exported_tar)
    cleanup_container(container)
    return container, log_file, fs_dir

def get_original(arvo_id: int, project:str, file_path: str):
    image = f'n132/arvo:{arvo_id}-vul'
    
    def run_cat(target_path):
        cmd = ['docker', 'run', '--rm', image, 'cat', target_path]
        return subprocess.run(cmd, capture_output=True, text=True, check=True)

    try:
        return run_cat(file_path).stdout

    except subprocess.CalledProcessError:
        project_path = str(Path(project) / file_path)
        logger.info(f'File not found at relative path, prepending project directory: {project_path}')
        try:
            return run_cat(project_path).stdout
        except subprocess.CalledProcessError as e:
            logger.error(f'Error reading file from container: {e}')
            return None

def get_container_cat(container_name: str, file_path: str):
    cmd = ['docker', 'exec', container_name, 'cat', file_path]
    try:
        result = run_command(cmd=cmd, stdout=subprocess.PIPE)
        return result.stdout
    except subprocess.CalledProcessError:
        logger.warning(f'File not found in continer: {file_path}')
        return None
    
# Running arvo_tools.py as main is currently disabled due to malfunction
# Code remains for convenience if debug testing is required

# if __name__ == "__main__":
#     setup_logger()
#     container = None
#     log_file = None
#     try:
#         container, log_file = initial_setup(42488087)
#         # container, log_file = load_container(42530547)
#         # exported_tar = export_container(container)
#         # extracted_path = extract_files(exported_tar, container, fix_flag=False)
#         # logging.info(f"Files extracted to {extracted_path}")

#     except Exception as e:
#         logging.error(f"An error occurred: {e}")
    
    # finally:
    #     if container:
    #         cleanup_container(container)
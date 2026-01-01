import logging
import os
from pathlib import Path
import subprocess
import sys
import time

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
        logger.info(f'Executing: {" ".join(cmd)}')
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

# change fix_flag to 'fix' to load the patched container
def load_container(arvo_id: int, fix_flag: str = 'vul'):
    # pull container first for concise crash_log
    pull_call = ['docker', 'pull', f'n132/arvo:{arvo_id}-{fix_flag}']
    logger.info(f"Pulling image n132/arvo:{arvo_id}-{fix_flag}")
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

def export_container(container_name: str):
    output_tar = f'{container_name}.tar'
    cmd = ['docker', 'export', container_name, '-o', output_tar]
    run_command(cmd)

    if not os.path.exists(output_tar):
        logger.error(f"Failed to export container {container_name} to {output_tar}")
        raise FileNotFoundError(f"{output_tar} not found after export")
    return output_tar

def extract_files(container_tar: str, container_name: str):     
    os.makedirs(container_name, exist_ok=True)
    logger.info(f"Extracting {container_tar} to {container_name}")
    
    cmd = ['tar', '-xf', container_tar, '-C', container_name]
    result = run_command(cmd, check=False)

    if result.returncode != 0:
        logger.warning(f"Process finished with abnormal exit code {result.returncode} for {container_tar}. Please manually verify project directory files are intact!")

    if not any(os.scandir(container_name)):
        logger.error(f"No files found in extracted directory {container_name}")
        raise FileNotFoundError(f"No files extracted to {container_name}")

def cleanup_tar(tar_path: str):
    if os.path.exists(tar_path):
        logger.info(f"Removing tar file {tar_path}")
        os.remove(tar_path)
    else:
        logger.warning(f"Tar file {tar_path} does not exist for cleanup")

def cleanup_container(container_name: str):
    logger.info(f"Cleaning up container {container_name}")
    cmd = ['docker', 'rm', '-f', container_name]
    run_command(cmd, check=False)

def standby_container(vuln_id: int, container_name: str, fix_flag: str = 'vul'):
    stby_cmd = ['docker', 'run', '-d',
                 '--name', container_name,
                 '--entrypoint', 'tail',
                 f'n132/arvo:{vuln_id}-{fix_flag}',
                 '-f', '/dev/null'
    ]
    logger.info(f"Starting standby container {container_name}")
    run_command(stby_cmd)

# helper function to move files in and out of docker containers
def docker_copy(container_name: str, src_path: str, dest_path: str, container_source_flag: bool):
    filename = Path(src_path).name
    # append -original to filename if copying from container
    # WARNING : this assumes the only occasion to extract files from container is to get original versions
    full_dest_path = Path(dest_path) / f'{filename}-original' if container_source_flag else Path(dest_path)
    if container_source_flag:
        copy_cmd = ['docker', 'cp', f'{container_name}:{src_path}', f'{full_dest_path}']
    # TODO / WARNING : the else path has not been tested yet 
    else:
        copy_cmd = ['docker', 'cp', src_path, f'{container_name}:{full_dest_path}']
    
    logger.info(f"Copying {'from' if container_source_flag else 'to'} container {container_name}: {src_path} -> {dest_path}")
    run_command(copy_cmd)


def initial_setup(arvo_id: int, fix_flag: str = 'vul'):
    container, log_file = load_container(arvo_id, fix_flag)
    exported_tar = export_container(container)
    extract_files(exported_tar, container)
    cleanup_tar(exported_tar)
    cleanup_container(container)
    return container, log_file

if __name__ == "__main__":
    setup_logger()
    container = None
    log_file = None
    try:
        container, log_file = initial_setup(42488087)
        # container, log_file = load_container(42530547)
        # exported_tar = export_container(container)
        # extracted_path = extract_files(exported_tar, container, fix_flag=False)
        # logging.info(f"Files extracted to {extracted_path}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
    
    # finally:
    #     if container:
    #         cleanup_container(container)
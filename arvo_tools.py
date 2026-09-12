from collections import deque
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional
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

def run_command(
    cmd: List[str], 
    container_name: Optional[str] = None, 
    check: bool = True, 
    stdout=None, 
    stderr=subprocess.PIPE, 
    timeout: Optional[int] = None,
    **kwargs
) -> subprocess.CompletedProcess:
    
    # Prepend docker exec if a container is specified
    if container_name:
        # Use -i if you plan to pass input via stdin, otherwise just exec is fine
        docker_prefix = ["docker", "exec"]

        if "input" in kwargs and kwargs["input"] is not None:
            docker_prefix.append("-i")
            
        docker_prefix.append(container_name)
        cmd = docker_prefix + cmd

    try:
        logger.debug(f'Executing: {" ".join(cmd)}')
        result = subprocess.run(
            cmd,
            stdout=stdout,
            stderr=stderr,
            text=True,
            timeout=timeout,
            check=check,
            **kwargs
        )
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f'Command failed with exit code: {e.returncode}')
        logger.error(f'Stderr: {e.stderr}')
        raise
    except subprocess.TimeoutExpired as e:
        logger.error(f'Command timed out: {e}')
        raise
    
# TODO: Remove this feature
def make_fs(container_name: str):
    fs_dir = os.path.join(os.getcwd(), 'scratch_fs', container_name)
    os.makedirs(fs_dir, exist_ok=True)
    return fs_dir

# TODO: Retire pull_call and verify log isn't cluttered 
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

def cleanup_dind(container_name: str, rootainer_name: str = 'rootainer'):
    logger.debug(f"Cleaning up container {container_name} in container {rootainer_name}")
    root_cmd = ['docker', 'exec', rootainer_name]
    target_cmd = ['docker', 'rm', '-f', container_name]
    full_cmd = root_cmd + target_cmd
    run_command(full_cmd, check=False)

def prune_dind_images(keep_vuln_id, rootainer_name: str = 'rootainer',
                      keep_flags=('vul', 'fix')) -> List[str]:
    """Drop resident n132/arvo images from rootainer's inner docker except the
    current vuln's, so a long campaign of distinct ids doesn't fill inner storage.

    The current vuln's images are kept so a usage-limit resume (which re-runs the
    same id) reuses the cached image instead of re-pulling it. Both -vul and -fix
    are kept: the campaign path only pulls -vul, but get_original/load_container
    can pull -fix.

    Assumes runs are serial (the runner's lockfile allows one campaign at a time).
    A manually launched concurrent run could make this target an in-use image;
    docker refuses to remove those, so the worst case is a logged warning.

    Best-effort, like cleanup_dind: docker failures are logged, never raised.
    Returns the tags actually removed.
    """
    root_cmd = ['docker', 'exec', rootainer_name]
    list_cmd = ['docker', 'images', 'n132/arvo', '--format', '{{.Repository}}:{{.Tag}}']
    result = run_command(root_cmd + list_cmd, check=False, stdout=subprocess.PIPE)

    if result.returncode != 0:
        logger.warning(f"Could not list arvo images in {rootainer_name}, skipping prune: "
                       f"{result.stderr}")
        return []

    keep = {f'n132/arvo:{keep_vuln_id}-{flag}' for flag in keep_flags}
    resident = [line.strip() for line in (result.stdout or '').splitlines() if line.strip()]
    stale = [tag for tag in resident if tag not in keep]

    if not stale:
        logger.debug(f"No stale arvo images to prune in {rootainer_name} "
                     f"(resident: {resident or 'none'})")
        return []

    logger.info(f"Pruning {len(stale)} stale arvo image(s) from {rootainer_name}, "
                f"keeping vuln {keep_vuln_id}: {stale}")
    removed = []
    for tag in stale:
        rmi_result = run_command(root_cmd + ['docker', 'rmi', '-f', tag], check=False)
        if rmi_result.returncode == 0:
            removed.append(tag)
        else:
            logger.warning(f"Failed to remove image {tag} from {rootainer_name}: "
                           f"{rmi_result.stderr}")
    return removed


def standby_container(container_name: str, vuln_id: int, fix_flag: str = 'vul',
                      timeout: Optional[int] = None):
    """Start a standby container on the host docker.

    `docker run` pulls the image implicitly when it is absent, and an arvo image
    is ~14 GB, so callers running unattended should pass a timeout. Without one
    an unreachable registry blocks forever.
    """
    stby_cmd = ['docker', 'run', '-d',
                '--privileged',
                 '--name', container_name,
                 '--entrypoint', 'tail',
                 f'n132/arvo:{vuln_id}-{fix_flag}',
                 '-f', '/dev/null'
    ]
    logger.debug(f"Starting standby container {container_name}")
    run_command(stby_cmd, timeout=timeout)


def prune_host_images(keep_vuln_id: Optional[int] = None,
                      keep_flags=('vul',)) -> List[str]:
    """Drop resident n132/arvo images from the HOST docker except the current
    vuln's, so a long verification batch of distinct ids doesn't fill the disk.

    Host counterpart to prune_dind_images. diff_tools.py talks to host docker via
    standby_container, so the rootainer pruning the campaign runner relies on does
    not cover it. An arvo image is ~14 GB, so 55 of them is ~780 GB; the
    container's own writable layer is only ~780 MB and is reclaimed on removal.

    Only '-vul' is kept by default: diff_tools.py never pulls '-fix'.

    Pass keep_vuln_id=None to remove every resident arvo image.

    Best-effort, like cleanup_container: docker failures are logged, never raised.
    Returns the tags actually removed.
    """
    list_cmd = ['docker', 'images', 'n132/arvo', '--format', '{{.Repository}}:{{.Tag}}']
    result = run_command(list_cmd, check=False, stdout=subprocess.PIPE)

    if result.returncode != 0:
        logger.warning(f'Could not list arvo images on the host, skipping prune: '
                       f'{result.stderr}')
        return []

    keep = ({f'n132/arvo:{keep_vuln_id}-{flag}' for flag in keep_flags}
            if keep_vuln_id is not None else set())
    resident = [line.strip() for line in (result.stdout or '').splitlines() if line.strip()]
    stale = [tag for tag in resident if tag not in keep]

    if not stale:
        logger.debug(f'No stale arvo images to prune on the host '
                     f'(resident: {resident or "none"})')
        return []

    logger.info(f'Pruning {len(stale)} arvo image(s) from the host'
                + (f', keeping vuln {keep_vuln_id}' if keep_vuln_id else '')
                + f': {stale}')
    removed = []
    for tag in stale:
        rmi = run_command(['docker', 'rmi', '-f', tag], check=False)
        if rmi.returncode == 0:
            removed.append(tag)
        else:
            logger.warning(f'Failed to remove host image {tag}: {rmi.stderr}')
    return removed

def standby_dind(container_name: str, vuln_id: int, fix_flag: str = 'vul'):
    dind_cmd = ['docker', 'exec', 'rootainer']
    stby_cmd = ['docker', 'run', '-d',
                 '--name', container_name,
                 '--entrypoint', 'tail',
                 f'n132/arvo:{vuln_id}-{fix_flag}',
                 '-f', '/dev/null'
    ]
    logger.debug(f"Starting standby container in rootainer {container_name}")
    full_cmd = dind_cmd + stby_cmd
    run_command(full_cmd)



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

def push_md_dict_to_container(files_dict: dict, container_name: str):
    # Writes a dictionary of files to a temporary folder and uses docker_copy to move them into container.
    
    # 1. Create a temporary directory that automatically deletes itself
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_path = Path(temp_dir_name)
        
        # 2. Extract the dictionary and write the files to the temporary folder
        for filename, file_content in files_dict.items():
            file_path = temp_path / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(file_content)
                
        # 3. Prepare the source path for your helper function
        # Adding '/.' tells Docker to copy the CONTENTS of the folder, not the folder itself
        source_path = f"{temp_dir_name}/."
        
        # 4. Call your existing project helper!
        try:
            docker_copy(
                container_name=container_name, 
                src_path=source_path, 
                dest_path='/opt/agent/', 
                container_source_flag=False  # False because we are copying TO the container
            )
            logger.info(f'markdown files successfully exported to {container_name}.')
            
        except Exception as e:
            logger.error(f"Failed to copy files using docker_copy helper: {e}")
            

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
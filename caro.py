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
from queries import get_context, insert_crash_log, insert_content, update_caro_log
from agent_tools import conduct_run
from arvo_tools import initial_setup, recompile_container, refuzz, standby_container, docker_copy, cleanup_container
from commit_files import download_commit_files
from schema import CrashLogType, ContentType


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caro.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

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

def collect_modified_files(modified_files, workspace, run_path, initial_prompt):
    for mod_file in modified_files:
        mod_filepath = Path(mod_file)
        if mod_filepath.exists():
            try:
                relative_path = mod_filepath.relative_to(workspace)
                # TODO: verify the next line's behavior is as intended
                flat_name = str(relative_path).replace('/', '__').replace('\\', '__')
                if initial_prompt:
                    new_name = f'{flat_name}-patch1' 
                else:
                    new_name = f'{flat_name}-patch2'
                dest_path = run_path / new_name
                shutil.copy2(mod_filepath, dest_path)
                logger.info(f'Copied modified file {mod_filepath} to {dest_path}')
            except Exception as e:
                logger.error(f'Error copying modified file {mod_filepath}: {e}')

if __name__ == "__main__":
    patch_url = None
    logger.info('######### Starting CARO Experiment Run #########')
    experiment_params = load_config()
    vuln_id = experiment_params.get('arvo_id')
    initial_prompt = experiment_params.get('initial_prompt') # flag
    agent = experiment_params.get('agent', 'codex')
    resume_flag = experiment_params.get('resume_flag', False) 

    # Get project and crash type from ARVO.db
    project, crash_type, patch_url = get_context(vuln_id)
    logger.info(f"Experiment setup for ARVO ID {vuln_id}: project={project}, crash_type={crash_type}, patch_url={patch_url}, initial_prompt={initial_prompt}, resume_flag={resume_flag}")
    # Does not check for patch url which isn't critical to execution
    if project is None or crash_type is None: 
        context_error = f"ERROR: Missing context - project is {project} and crash_type is {crash_type} for ID {vuln_id}. Execution aborted."
        logger.error(context_error)
        raise ValueError(context_error)
    
    logger.info(f'Generating original arvo crash log and extracting filesystem.')
    container, crash_original, fs_dir = initial_setup(vuln_id)
    workspace = Path(fs_dir) / 'src' / project

    # Use experiment_setup.json to indicate if this is an initial prompt
    if initial_prompt:
        prompt = f'Find and fix the bug in {project} to remove the {crash_type} shown in the log below. Provide the lines of code and file locations changed in this task.'

        crash_path = Path(__file__).parent / crash_original
        logger.info(f'Reading crash log from {crash_path}')
        try:
            with open(crash_path, "r", encoding="utf-8", errors="replace") as f:
                crash_log = f.read()
        except FileNotFoundError:
            logger.error(f"Error: The file {crash_path} was not found.")

        prompt += f'<crash_log>{crash_log}</crash_log>'

        # conduct the experiment
        modified_files = conduct_run(vuln_id, container, prompt, workspace, agent=agent, resume_flag=False, patch_url=patch_url)

        # send crash_log to run db
        insert_crash_log(container, CrashLogType.ORIGINAL, crash_log)

        run_path = Path(__file__).parent / 'runs' / container

        # move crash log to run folder for archiving
        try:
            shutil.move(crash_path, run_path)
        except Exception as e:
            logger.error(f'Error moving crash log to run folder. Move manually or regenerate: {e}')

        # download ground truth from repo commit url
        try:
            ground_truth_files = download_commit_files(patch_url, run_path)
            # send ground truth files to db
            for gt_file in ground_truth_files:
                gt_path = Path(gt_file)
                logger.debug(f'gt_path{gt_path}')

                try:         
                    relative_path = gt_path.relative_to(run_path)
                    logger.debug(f'relative_path_str: {relative_path}')
                    truncated_gt_path = Path(*relative_path.parts[1:])  # remove 'grndtrth' folder for db path
                    logger.debug(f'truncated_gt_path for db: {truncated_gt_path}')

                    with open(gt_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                        insert_content(run_id=container, file_path=str(truncated_gt_path), kind=ContentType.GROUND_TRUTH, content=content)
                except ValueError:
                    logger.error(f'Path error: GT file at {gt_path} is not inside {run_path}')

                except Exception as e:
                    logger.error(f'Error reading ground truth file {gt_file} for database insertion: {e}')
        except Exception as e:
            logger.error(f'Skipping download. Error getting commit files from {patch_url}: {e}')
        
        



        # copy modified files to experiment run folder for archiving
        collect_modified_files(modified_files, workspace, run_path, initial_prompt=True)
        # TODO: add logic saving data to database and csv

    # logic for second attempt at patching
    else:
        prompt = 'Your previous fixes did not remove the crash.'
        resume_id = experiment_params.get('resume_id', None)
        crash_log_patch = experiment_params.get('crash_log_patch', None)
        additional_context = experiment_params.get('additional_context', '')
        if crash_log_patch:
            crash_path = Path(crash_log_patch)
            if crash_path.exists():
                logger.debug(f"Reading first attempt's crash log from {crash_path}")
                try:
                    with open(crash_path, "r", encoding="utf-8", errors="replace") as f:
                        crash_log = f.read()
                        prompt = 'Your previous fixes did not remove the crash as indicated by this new crash log:'
                        prompt += f'<crash_log>{crash_log}</crash_log>'
                except FileNotFoundError:
                    logger.error(f"Error: The file {crash_path} was not found.")
        

        prompt += 'The workspace has been reset with the original files.' 
        if additional_context:
            prompt += additional_context
        # Example second try context: A known correct fix made changes to the following files: src/internal.c around lines 21167 - 21171, 23224, 25164 and 25176; wolfcrypt/src/dh.c near lines 1212, 1244, 1284 and 1289; and wolfcrypt/test/test.c near lines 14644, 14766 and 14812.
        prompt += 'Use this information to reattempt the fix.'

        modified_files = conduct_run(vuln_id, container, prompt, workspace, agent=agent, resume_flag=True, resume_session_id=resume_id, patch_url=patch_url)
        run_path = Path(__file__).parent / 'runs' / container

        # copy modified files to experiment run folder for archiving
        collect_modified_files(modified_files, workspace, run_path, initial_prompt=False)

    # following executes for both first and subsequent attempts

    # must truncate local path for container compatibility
    base_to_remove = workspace.parents[1]
    
    # run container indefinitely and extract original copies of modified files if first attempt
    try:
        patch_container = f'{container}-patch'
        standby_container(patch_container, vuln_id)
        logger.debug(f'Standby container {patch_container} started for patch evaluation.')
        logger.debug(f'initial_prompt is {initial_prompt}')
        if initial_prompt:
            logger.info('Copying original container files')
            for mod_file in modified_files:
                mod_filepath = Path(mod_file)
                filename = mod_filepath.name
                # rel_path will be src/{project}/...
                relative_path = mod_filepath.relative_to(base_to_remove)
                truncated_path = Path(*relative_path.parts[2:])  # remove 'src' and project folder for container path
                logger.debug(f'chopping relative path {relative_path} to {truncated_path} for db')

                # insert original file into db
                with open(mod_filepath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

                    insert_content(run_id=container, file_path=str(truncated_path), kind=ContentType.ORIGINAL, content=content)

                logger.debug(f'docker copy original file {relative_path} to {run_path}/{filename}-original')
                docker_copy(patch_container, str(relative_path), run_path, container_source_flag=True)

    except Exception as e:
        logger.error(f'Error docker copying original files: {e}')

    # copy the modified files into the container
    for mod_file in modified_files:
        mod_filepath = Path(mod_file)
        filename = mod_filepath.name
        relative_path = mod_filepath.relative_to(base_to_remove)
        truncated_path = Path(*relative_path.parts[2:])  # remove 'src' and project folder for container path
        logger.debug(f'chopping relative path {relative_path} to {truncated_path} for db')

        # insert patched file into db
        with open(mod_filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

            insert_content(run_id=container, file_path=str(truncated_path), kind=ContentType.PATCHED, content=content)

        logger.debug(f'docker copy modified file {mod_filepath} to container at {relative_path}')
        docker_copy(patch_container, str(mod_filepath), str(relative_path), container_source_flag=False)

    # re-compile
    recompile_container(patch_container)
    # TODO : Explore how much we need to verify compile success
    # Will compile failure automatically result in re-fuzz crash?

    # re-run poc and capture new crash/success log
    fuzz_result = refuzz(patch_container)

    insert_crash_log(run_id=container, kind=CrashLogType.PATCH, crash_log=fuzz_result.stderr)
    
    crash_log_path = f'runs/crash_log_{patch_container}.log'
    # crash_log_path = run_path / 'crash_first_patch.log'
    logger.debug(f'Writing first patch crash log to {crash_log_path}')
    logger.info(f'arvo (re-run poc) stderr:\n{fuzz_result.stderr}')
    with open(crash_log_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(fuzz_result.stderr)

    logger.debug(f'removing patch container {patch_container}')
    cleanup_container(patch_container)
    fs_path = Path(fs_dir)
    if fs_path.exists() and fs_path.is_dir():
        logger.debug(f'removing extracted filesystem at {fs_path}')
        shutil.rmtree(fs_path, ignore_errors=True)

    logger.info('######### CARO Experiment Run Complete #########')

    caro_dir = Path(__file__).parent

    caro_log_path = caro_dir / 'caro.log'

    # update caro_log in db
    try:
        update_caro_log(container, str(caro_log_path))
    except Exception as e:
        logger.error(f'Error updating caro_log in database for run {container}: {e}')

    # will want to use same run folder as first attempt?
    # QUESTION: regenerate original workspace for second attempt?
    # if the agent's patch did not resolve the crash are its changes benign or necessitate more fixes?
    # For now agent's second attempt will start from original codebase again
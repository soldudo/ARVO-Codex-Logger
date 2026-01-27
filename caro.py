import logging
import json
import os
import shutil
import sys
from pathlib import Path
import time
from queries import get_context, insert_crash_log, update_caro_log, get_crash_log, get_resume_id, update_patch, update_original, update_ground_truth
from agent_tools import conduct_run
from arvo_tools import initial_setup, recompile_container, refuzz, standby_container, docker_copy, cleanup_container, get_original, get_container_cat
from commit_files import download_commit_files
from schema import CrashLogType, ContentType


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caro.log", mode='a'),
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
    container_name = experiment_params.get('container_name')
    initial_prompt = experiment_params.get('initial_prompt') # flag
    agent = experiment_params.get('agent', 'codex')
    resume_flag = experiment_params.get('resume_flag', False) 
    
    # Defining the run name (previously container) using arvo-vuln_id-vuln_flag-timestamp
    run_id = f'arvo-{vuln_id}-vul{int(time.time())}'

    # Get project and crash type from ARVO.db
    project, crash_type, patch_url = get_context(vuln_id)
    logger.info(f"Experiment setup for ARVO ID {vuln_id}: project={project}, crash_type={crash_type}, patch_url={patch_url}, initial_prompt={initial_prompt}, resume_flag={resume_flag}")
    # Does not check for patch url which isn't critical to execution
    if project is None or crash_type is None: 
        context_error = f"ERROR: Missing context - project is {project} and crash_type is {crash_type} for ID {vuln_id}. Execution aborted."
        logger.error(context_error)
        raise ValueError(context_error)

    # Use experiment_setup.json to indicate if this is an initial prompt
    if initial_prompt:
        prompt = f'Find and fix the bug in {project} to remove the {crash_type} shown in the crash.log file. Provide the lines of code and file locations changed in this task. '

        # conduct the experiment
        modified_files = conduct_run(vuln_id=vuln_id, run_id=run_id, container_name=container_name, prompt=prompt, agent=agent, resume_flag=False, patch_url=patch_url)

        # copy original versions of modified files to db
        for m_file in modified_files:
            logger.info(f'Getting cat for m_file: {m_file}')
            content = get_container_cat(container_name, m_file)
            # update db with patch content
            logger.info(f'updating {run_id}\nfile {m_file}')
            update_patch(run_id=run_id, file_path=str(m_file), content=content)

            original_file = get_original(vuln_id, project, m_file)  

            if original_file is None:
                logger.info(f'{m_file} not found in container, skipping..')
                continue

            logger.info(f'File: {m_file}')
            logger.debug('Excerpt: \n%s', original_file[:300])
            update_original(vuln_id=vuln_id, file_path=m_file, content=original_file)
            
        run_path = Path(__file__).parent / 'runs' / run_id

        # download ground truth from repo commit url
        try:
            ground_truth_files = download_commit_files(patch_url, run_path)
            # send ground truth files to db
            for gt_file in ground_truth_files:
                gt_path = Path(gt_file)
                logger.debug(f'gt_path{gt_path}')

                try:         
                    relative_path = gt_path.relative_to(run_path)
                    logger.info(f'relative_path_str: {relative_path}')
                    truncated_gt_path = Path(*relative_path.parts[1:])  # remove 'grndtrth' folder for db path
                    logger.info(f'truncated_gt_path for db: {truncated_gt_path}')

                    with open(gt_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                        update_ground_truth(vuln_id=vuln_id, file_path=str(truncated_gt_path), content=content)
                        
                except ValueError:
                    logger.error(f'Path error: GT file at {gt_path} is not inside {run_path}')

                except Exception as e:
                    logger.error(f'Error reading ground truth file {gt_file} for database insertion: {e}')
        except Exception as e:
            logger.error(f'Skipping download. Error getting commit files from {patch_url}: {e}')

    # TODO: Still needs updated container implementation to match first try run
    # DO NOT RUN SECOND ATTEMPTS UNTIL THIS IS FIXED!
    # logic for second attempt at patching
    else:
        prompt = 'Your previous fixes did not remove the crash. '
        # load experiment settings from json
        resume_id = experiment_params.get('resume_id', None)
        source_crash_flag = experiment_params.get('source_crash_db', False)
        run_id_prev = experiment_params.get('run_id', None)
        source_resume_id = experiment_params.get('source_resume_db', False)
        crash_log_patch = experiment_params.get('crash_log_patch', None)
        additional_context = experiment_params.get('additional_context', '')

        # if flag true get prev patch crash from db
        if source_crash_flag and run_id_prev:
            crash_log = get_crash_log(run_id=run_id_prev, kind=CrashLogType.PATCH)
            logger.debug(f'Loaded prev patch crash log: {crash_log}')
            if source_resume_id:
                resume_id = get_resume_id(run_id=run_id_prev)
                logger.info(f'Query produced resume_id: {resume_id}')

        # fallback on loading crash from file
        elif crash_log_patch:
            crash_path = Path(crash_log_patch)
            if crash_path.exists():
                logger.debug(f"Reading first attempt's crash log from {crash_path}")
                try:
                    with open(crash_path, "r", encoding="utf-8", errors="replace") as f:
                        crash_log = f.read()
                        prompt = 'Your previous fixes did not remove the crash as indicated by this new crash log: '
                        prompt += f'<crash_log>{crash_log}</crash_log>'
                except FileNotFoundError:
                    logger.error(f"Error: The file {crash_path} was not found.")
        
        prompt += ' The workspace has been reset with the original files. ' 
        if additional_context:
            prompt += additional_context
        # Example second try context: A known correct fix made changes to the following files: src/internal.c around lines 21167 - 21171, 23224, 25164 and 25176; wolfcrypt/src/dh.c near lines 1212, 1244, 1284 and 1289; and wolfcrypt/test/test.c near lines 14644, 14766 and 14812.
        prompt += ' Use this information to reattempt the fix.'

        # get list of files modified since start of run. relative paths used for navigating container and db
        modified_files = conduct_run(vuln_id=vuln_id, container_name=container_name, prompt=prompt, agent=agent, resume_flag=True, resume_session_id=resume_id, patch_url=patch_url)
        
        for m_file in modified_files:
            content = get_container_cat(container_name, m_file)
            # update db with patch content

            update_patch(run_id=run_id, file_path=str(m_file), content=content)

        # TODO look into deleting later
        run_path = Path(__file__).parent / 'runs' / run_id

    # re-compile
    recompile_container(container_name)
    # TODO : Explore how much we need to verify compile success
    # Will compile failure automatically result in re-fuzz crash?

    # re-run poc and capture new crash/success log
    fuzz_result = refuzz(container_name)

    insert_crash_log(run_id=run_id, kind=CrashLogType.PATCH, crash_log=fuzz_result.stderr)

    logger.info('######### CARO Experiment Run Complete #########')

    caro_dir = Path(__file__).parent

    caro_log_path = caro_dir / 'caro.log'

    # update caro_log in db
    try:
        update_caro_log(run_id, str(caro_log_path))
    except Exception as e:
        logger.error(f'Error updating caro_log in database for run {run_id}: {e}')

    # will want to use same run folder as first attempt?
    # QUESTION: regenerate original workspace for second attempt?
    # if the agent's patch did not resolve the crash are its changes benign or necessitate more fixes?
    # For now agent's second attempt will start from original codebase again
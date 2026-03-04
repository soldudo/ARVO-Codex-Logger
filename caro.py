import logging
import json
import os
import shutil
import sys
from pathlib import Path
import time
from queries import get_context, update_caro_log, update_patch, update_original, update_ground_truth
from agent_tools import conduct_run
from arvo_tools import get_original, get_container_cat
from commit_files import download_commit_files

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
    
    # Definine the run name (previously container) as arvo-vuln_id-vuln_flag-timestamp
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
        # localization only prompt
        prompt = f'Investigate the memory safety vulnerability causing the {crash_type} in the {project} project as shown in the opt/agent/crash.log file. Please initialize your environment using the opt/agent/memory_safety_agent.md persona. Use the patterns and checklist provided in the opt/agent/memory_safety_skills.md file. Both markdown files are located in the root folder. Localize the source causing this crash by providing the relevant files, functions and lines.'

        # conduct the experiment
        conduct_run(vuln_id=vuln_id, run_id=run_id, container_name=container_name, prompt=prompt, agent=agent, resume_flag=False, patch_url=patch_url)

        # copy original versions of modified files to db
        
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

    logger.info('######### CARO Experiment Run Complete #########')
    caro_dir = Path(__file__).parent
    caro_log_path = caro_dir / 'caro.log'

    # update caro_log in db
    try:
        update_caro_log(run_id, str(caro_log_path))
    except Exception as e:
        logger.error(f'Error updating caro_log in database for run {run_id}: {e}')
import argparse
import logging
import json
import os
import tempfile
import sys
from pathlib import Path
import time
from queries import get_context, update_caro_log, get_result_json, get_experiment_artifacts
from agent_tools import conduct_run
from arvo_tools import push_md_dict_to_container
from run_parser import parse_agent_run

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caro.log", mode='w'), # recommend mode='w' otherwise multiple run logs will be stored for one run in db
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_config(config_path=None):
    if config_path is None:

        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, 'experiment_setup.json')

    if not os.path.exists(config_path):
        logger.critical(f"Config file not found at {config_path}")
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            data = json.load(f)
            logger.info(f'loaded experiment parameters: {data}')
            return data
            
    except json.JSONDecodeError as e:
        logger.critical(f"JSON file is corrupt or invalid: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=None, help='Path to experiment config JSON')
    args = parser.parse_args()
    patch_url = None
    logger.info('######### Starting CARO Experiment Run #########')
    
    caro_dir = Path(__file__).parent
    caro_log_path = caro_dir / 'caro.log'

    experiment_params = load_config(args.config)
    experiment_tag = experiment_params.get('experiment_tag')
    vuln_id = experiment_params.get('arvo_id')
    container_name = experiment_params.get('container_name', 'rootainer')
    agent = experiment_params.get('agent', 'claude')
    is_loc_mode = experiment_params.get('is_loc_mode', True)
    is_patch_mode = experiment_params.get('is_patch_mode', False)
    loc_run_id = experiment_params.get('loc_run_id', None)
    is_resume = experiment_params.get('is_resume', False) 
    resume_id = experiment_params.get('resume_id', None)

    if not vuln_id or not isinstance(vuln_id, int):
        arvoId_error = f'ERROR: Invalid arvo vulnerability id: {vuln_id}'
        logger.critical(arvoId_error)
        raise ValueError(arvoId_error)

    prompts_dict, markdowns_dict = get_experiment_artifacts(experiment_tag)

    push_md_dict_to_container(markdowns_dict, container_name)

    # If patching run either need to localize first, or have loc_run_id or be resuming a previous session (presumably with that context)
    if is_patch_mode and not (is_loc_mode or loc_run_id):
        if not is_resume:
            missing_loc_run_id_error = f'Warning: Missing run_id for location context (and session not resumed from prev state). If experiment should have localization context please correct settings and re-run.'
            logger.warning(missing_loc_run_id_error)
        else:
            logger.warning('WARNING: localization result not provided. Cannot verify it was passed previously to resumed state.')
    
    # Definine the run name (previously container) as arvo-vuln_id-vuln_flag-timestamp
    run_id = f'arvo-{vuln_id}-vul-{int(time.time())}'
    logger.info(f'Experiment assigned run_id: {run_id}')

    # Get project and crash type from ARVO.db
    project, crash_type, patch_url = get_context(vuln_id)
    logger.info(f"Experiment setup for ARVO ID {vuln_id}: project={project}, crash_type={crash_type}, patch_url={patch_url}")
    # Does not check for patch url which isn't critical to execution
    if project is None or crash_type is None: 
        context_error = f"ERROR: Missing context - project is {project} and crash_type is {crash_type} for ID {vuln_id}. Execution aborted."
        logger.error(context_error)
        raise ValueError(context_error)
    
    # Warning in case localization to be performed, but previous result also supplied
    if is_loc_mode and loc_run_id:
        logger.warning(f'WARNING: caro running in localization mode, but a previous loc result was also provided.')

    # get localization context from db if patching enabled and previous run_id entered
    loc_context = None
    if is_patch_mode and loc_run_id:

        db_loc_result = get_result_json(loc_run_id)

        is_context_valid = False
        loc_error_msg = ''

        if db_loc_result is None:
            loc_error_msg = f'No localization result found in DB for run_id: {loc_run_id}'
        # If fetched vuln_id does not match experiment's vuln_id 
        elif db_loc_result[1] != vuln_id:
            loc_error_msg = f'Provided run_id {loc_run_id} fetched vuln_id: {db_loc_result[1]} which does not match experiment\'s vuln_id: {vuln_id}'
        
        else:
            loc_context = json.loads(db_loc_result[0])
            loc_error_msg = f'Localization result for DB run_id {loc_run_id} is empty.'
            if loc_context:
                # Found valid context
                logger.info(f'Successfully loaded previous run {loc_run_id} localization context.')
                logger.debug(loc_context)
                is_context_valid = True
                # remove confidence scores (arbitrary and we're not asking for related behavior)
                logger.debug('Removing confidence scores from previous run loc_context')
                for vuln in loc_context.get("vulnerabilities", []):
                    vuln.pop("confidence_score", None)

        if not is_context_valid:
            logger.error(f'Localization context ERROR: {loc_error_msg}')

            if not is_loc_mode:
                raise ValueError(f'Experiment FAILED: {loc_error_msg}')
            else: 
                logger.warning('Experiment proceeding since localization mode enabled. Previous loc context discarded due to vuln_id mismatch. Generating new localization context.')

    # If flagged execute localization run and then patching run ()
    current_loc_run_id = None

    # localization mode
    if is_loc_mode:
        loc_is_resume = is_resume
        loc_resume_id = resume_id
        # if valid localization context fetched, we use that instead of generating new one
        if loc_context is not None:
            logger.info(f'Localization context fetched from DB from provided loc_run_id. Skipping localization run. (Remove loc_run_id from experiment_setup.json to ensure new localization run generates.')

        else:
            # conduct localization experiment
            if not is_resume:
                raw_loc_prompt = prompts_dict.get('loc')
                if raw_loc_prompt is None:
                    logger.error('Error: no localization prompt found')
                    raise ValueError('Error: no localization prompt found. Experiment failure, exiting..')
                prompt = eval(f'f"""{raw_loc_prompt}"""')
            else:
                prompt = 'continue where you left off'
                # ensure any subsequent patching run doesn't try to continue the used resume session
                is_resume = False
                resume_id = None

            current_loc_run_id = run_id + '-loc'

            loc_run_params = {
                "experiment_tag": experiment_tag,
                "vuln_id": vuln_id,
                "run_id": current_loc_run_id,
                "container_name": container_name,
                "prompt": prompt,
                "agent": agent,
                "run_mode": 'loc',
                "is_resume": loc_is_resume,
                "resume_session_id": loc_resume_id,
            }

            logger.info('Conducting localization run')
            logger.debug(f'Run parameters: {loc_run_params}')

            try:
                parse_agent_run(conduct_run(**loc_run_params))
                
                logger.info('######### CARO Localization Run Complete #########')

                update_caro_log(run_id=current_loc_run_id, caro_log_path=str(caro_log_path))

            except Exception as e:
                logger.error(f'Error encountered: {e}')

    # patching run
    if is_patch_mode:

        if not is_resume:
            if not loc_context:
                if current_loc_run_id is not None:
                    logger.info('Getting localization context from the localization run that just completed.')
                    current_loc_result = get_result_json(current_loc_run_id)
                    if current_loc_result:
                            loc_context = json.loads(current_loc_result[0])
                            loc_run_id = current_loc_run_id
                else:
                    logger.info('No localization context available.')

            if loc_context:        
                # remove confidence scores (arbitrary and we're not asking for related behavior)
                logger.debug('Removing confidence scores from localization context')
                if loc_context:
                    for vuln in loc_context.get('vulnerabilities', []):
                        vuln.pop("confidence_score", None)

            # patch prompt
            raw_patch_prompt = prompts_dict.get('patch')
            if raw_patch_prompt is None:
                logger.error('Error: no patch prompt found')
                raise ValueError('Error: no patch prompt found. Experiment failure, exiting..')
            prompt = eval(f'f"""{raw_patch_prompt}"""')
        
        else:
            prompt = 'continue where you left off'

        patch_run_prams = {
            "experiment_tag": experiment_tag,
            "vuln_id": vuln_id,
            "run_id": run_id + '-patch',
            "container_name": container_name,
            "prompt": prompt,
            "agent": agent,
            "run_mode": 'patch',
            "loc_run_id": loc_run_id,
            "is_resume": is_resume,
            "resume_session_id": resume_id,
        }
        logger.info('Conducting patch run...')
        logger.debug(f'Run parameters: {patch_run_prams}')

        try:
            parse_agent_run(conduct_run(**patch_run_prams))

            logger.info('######### CARO Patch Run Complete #########')
            update_caro_log(run_id=run_id + '-patch', caro_log_path=str(caro_log_path))

        except Exception as e:
            logger.error(f'Error encountered: {e}')

from datetime import datetime
import json
import logging
from pathlib import Path
from arvo_tools import standby_dind, cleanup_dind, prune_dind_images
from queries import get_original_crash_log
import subprocess
import time

logger = logging.getLogger(__name__)

# This would only be used for Codex runs
def get_model(container_name: str):
    agent_model = None
    command = ['docker', 'exec', container_name, 'codex', 'exec', '/status']
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

def get_pwd(container_name: str):
    pwd_cmd = ['docker', 'exec', container_name, 'pwd']
    try:
        result = subprocess.run(pwd_cmd, capture_output=True, text=True)
        workspace_relative = result.stdout.strip()
        logger.debug(f'workspace_relative is {workspace_relative}')
        return workspace_relative
    except subprocess.CalledProcessError as e:
        logger.error(f'container {container_name} pwd failed: {e}')

# This needs to be refactored now that it's a separate function. Variables need to be persisted       
def process_codex_event(event):
    try:
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
        print(f'Non-JSON output: {event}')



# is_resume = True when instructing agent to resume last or specified session
# if flag is true, but id is none, last will be used
# def conduct_run(vuln_id: str, run_id: str, container_name: str, prompt: str, agent: str, run_mode: str, is_resume: bool = False, resume_session_id: str =None):

def conduct_run(experiment_tag, vuln_id, run_id, container_name, prompt, agent, run_mode, loc_run_id=None, is_resume=False, resume_session_id=None):
    # vuln_id=run_params.vuln_id
    # run_id=run_params.run_id
    # agent=run_params.agent
    # run_mode=run_params.run_mode
    # loc_run_id=run_params.loc_run_id
    # prompt=run_params.prompt
    # is_resume=run_params.is_resume
    # resume_session_id=run_params.resume_session_id

    # in case previous run crashed. Handle this better
    cleanup_dind('vulnscan')

    # free disk before the next image is pulled; keeps this vuln's image cached
    prune_dind_images(vuln_id)

    standby_dind(container_name='vulnscan', vuln_id=vuln_id)

    # TODO: Add robust handling & failsafe of crash_log copy to container
    crash_log_original = get_original_crash_log(vuln_id)

    copy_crash_cmd = ['docker', 'exec', '-i', 'rootainer', 'sh', '-c', 'cat > opt/agent/crash.log']
    process = subprocess.Popen(
        copy_crash_cmd,
        stdin=subprocess.PIPE,
        text=True
    )
    process.communicate(input=crash_log_original)
    
    if process.returncode == 0:
        logger.info("Original crash log copied into rootainer successfully.")

    if (agent == 'claude'):
        agent_args = ['claude', '-p', prompt]
        
        # Handle resuming a previous session
        if is_resume and resume_session_id:
            agent_args += ['--resume', resume_session_id]
        # resume previous session if no session_id passed
        elif is_resume and not resume_session_id:
            agent_args += ['--continue']
        agent_args += ['--output-format', 'json']

    # not currently using codex
    elif (agent == 'codex'):
        agent_model = get_model(container_name)
        agent_args = ['codex', 'exec', '--json', '--full-auto', prompt]

    command = ['docker', 'exec', container_name] + agent_args

    log_path = Path(__file__).parent / "runs" / run_id / f"agent_{run_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f'Logging to {log_path}\n')
    logger.debug(f"Invoking agent with: {command}")
    
    start_time = int(time.time())
    duration = 0
    return_code = None

    meta_start = {
            'log_type': 'session_start',
            'timestamp_iso': datetime.now().isoformat(timespec='seconds'),
            'timestamp_unix': start_time,
            'experiment_tag': experiment_tag,
            'vuln': vuln_id,
            'command': command,
            'run_mode': run_mode,
            'loc_run_id': loc_run_id,
            'prompt': prompt
        }

    with open(log_path, 'w', encoding='utf-8') as log_file:
        
        log_file.write(json.dumps(meta_start) + '\n')
        log_file.flush()
        logger.info(f'Beginning {agent} execution for {run_id}')

        # this command is formatted for docker exec
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
                    'log_type': 'agent_output',
                    'timestamp_iso': datetime.now().isoformat(timespec='seconds'),
                    'timestamp_unix': int(time.time()),
                    'data': None
                }

                try:
                    event = json.loads(line)
                    log_entry['data'] = event
                    
                    # codex not currently used
                    if agent == "codex":
                        process_codex_event(event)

                except Exception as e:
                    print(f'Error processing stdout line: {e}')
                    log_entry['data'] = {'raw_text': line}
                    continue
                
                log_file.write(json.dumps(log_entry) + '\n')
                log_file.flush()
                
            return_code = process.wait()
            end_time = int(time.time())
            duration = end_time - start_time

            logger.info(f'Coding agent run completed with return code {return_code} in {duration} seconds.')

            stderr_output = process.stderr.read()
            if stderr_output:
                print(f'\n{agent} stderr output:\n', stderr_output)
                log_file.write(json.dumps({
                    'log_type': 'stderr_output',
                    'timestamp_iso': datetime.now().isoformat(timespec='seconds'),
                    'timestamp_unix': int(time.time()),
                    'data': stderr_output
                }) + '\n')
                # log_file.flush() # copilot rec
            
            print(f'{agent} finished with return code {return_code} in {duration} seconds.')

        except Exception as e:
            logger.error(f'Error during {agent} execution: {e}')
            print(f'Error during {agent} execution: {e}')
            log_file.write(json.dumps({
                'log_type': 'execution_error',
                'timestamp_iso': datetime.now().isoformat(timespec='seconds'),
                'timestamp_unix': int(time.time()),
                'data': str(e)
            }) + '\n')
            raise e
                
        finally:

            # run metrics
            meta_end = {
                'log_type': 'session_end',
                'timestamp_iso': datetime.now().isoformat(timespec='seconds'),
                'timestamp_unix': int(time.time()),
                'duration_seconds': duration,
                'return_code': return_code,
            }
            log_file.write(json.dumps(meta_end) + '\n')
            log_file.close()
            logger.info(f'{agent} run log saved to {log_path}')

            try:
                with open(log_path, 'r', encoding='utf-8') as f_read:
                    agent_log = f_read.read()

            except Exception as e:
                logger.error(f'Error reading agent log for db storage: {e}')
                agent_log = ''

            # wipe arvo container in rootainer
            cleanup_dind('vulnscan')

    return log_path
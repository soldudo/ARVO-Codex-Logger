import logging
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from queries import get_context, insert_crash_log, update_caro_log, get_crash_log, get_resume_id, update_patch, update_original, update_ground_truth
from agent_tools import conduct_run, get_pwd
from arvo_tools import initial_setup, recompile_container, refuzz, standby_container, docker_copy, cleanup_container, get_original
from commit_files import download_commit_files
from schema import CrashLogType, ContentType

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caro_inject_test.log", mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

vuln_id = 42528951
container_name = f'a-{vuln_id}'

# prompt = f'Find and fix the bug in libxml2 to remove the Heap-buffer-overflow crash. Provide the lines of code and file locations changed in this task. '


standby_container(container_name=container_name, vuln_id=vuln_id)
time.sleep(2)

setup_commands = [
    # Install prerequisites
    "apt-get update && apt-get install -y curl git",
    
    # Install Node.js 22 (Pipe explicitly handled via bash -c later)
    "curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs",
    
    # Install Codex CLI
    "npm install -g @openai/codex"
]

def run_command(container, cmd):
    logger.debug(f"Executing: {cmd[:50]}...")
    # We wrap in bash -c to handle pipes (|) and chains (&&) correctly
    result = subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        logger.error(f"Error: {result.stderr}")
        raise Exception("Command failed")
    logger.info(f"Successfully ran {cmd} on {container}.")

# copy original crash log into container for agent to find
crash_log = 'crash.log'
project_dir = get_pwd(container_name)
docker_copy(container_name, crash_log, project_dir, container_source_flag=False)

# TODO: update to iterate over list of containers to start

# 3. Iterate through the list
try:
    for cmd in setup_commands:
        run_command(container_name, cmd)
    logger.info("\nEnvironment is ready. You can now run the Codex CLI.")
except Exception as e:
    logger.error(f"Setup failed: {e}")






# log_path = './agent_log.log'

# cmd = ['docker', 'exec', container_name, 'codex', 'exec', '--json', '--full-auto', prompt]

# process = subprocess.Popen(
#             cmd,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#             text=True,
#             bufsize=1
#         )

# with open(log_path, 'w', encoding='utf-8') as log_file:
#     for line in process.stdout:
#         line = line.rstrip('\n')
        
#         if not line.strip():
#             continue
        
#         try:
#             log_entry = json.loads(line)
#             log_file.write(json.dumps(log_entry) + '\n')
#             log_file.flush()

#         except json.JSONDecodeError as e:
#             logger.error(f'Error: {e}\n From line: {line}')

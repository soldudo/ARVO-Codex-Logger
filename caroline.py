import subprocess
import json
import time
from pathlib import Path
from typing import Optional
from queries import get_context

# Windows workaround
CODEX_PS1_PATH = r"C:\Users\apruf\AppData\Roaming\npm\codex.ps1"

vuln = 'n132-arvo-42528804-vul'
vuln_id = 42528804


project, crash_type, crash_output = get_context(vuln_id)
prompt = f'You are a security-focused code assistant tasked with finding and patching the {project} vulnerability within the current working directory.'

# Provide context from arvo's fuzzer
if crash_type and crash_output:
    prompt += f'To aid this task a fuzzer was used and produced a crash of type {crash_type} with the following output:\n{crash_output}\n'
prompt += 'After analyzing the codebase and fuzzing results, generate a patch to fix the vulnerability. Provide only the code changes in a unified diff format without any additional explanations or text.'

def conduct_run(vuln: str, prompt: str, context: Optional[str] = None):
    log_path = Path(__file__).parent / "runs" / f"{vuln}-{int(time.time())}.log"
    workspace = Path(__file__).parent / vuln
    command = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), prompt]

    windows_fix = ['powershell', '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', CODEX_PS1_PATH] + command[1:]

    if context:
        command.append(context)
    print("About to run:", command)
    log_file = open(log_path, 'w', encoding='utf-8')

    start_time = time.time()

    process = subprocess.Popen(
        windows_fix, # switch to command on linux server
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    print(f'Writing log to {log_path}\n')

    try:
        for line in process.stdout:
            line = line.rstrip('\n')
            log_file.write(line + '\n')
            log_file.flush()
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f'Non-JSON output: {line}')
                continue
            
            # Consider adding timestamp to log entries by writing wrapped json
            # timed_event = {
            #     'timestamp': time.time(),
            #     'event': event
            # }

            event_type = event.get('type')
            print(f'Event: {event_type}')
            
        return_code = process.wait()
        end_time = time.time()
        duration = end_time - start_time
        print(f'Codex finished with return code {return_code} in {duration:.2f} seconds.')

        stderr_output = process.stderr.read()
        if stderr_output:
            print('\nCodex stderr output:\n', stderr_output)
    
    finally:
        log_file.write(f'*** Codex finished. Elapsed time: {duration} seconds ***')
        log_file.close()

if __name__ == "__main__":
    conduct_run(vuln, prompt)
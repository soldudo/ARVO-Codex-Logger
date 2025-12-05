import subprocess
import json
import time
from pathlib import Path
from typing import Optional

vuln = 'n132-arvo-42528804-vul'
prompt = 'You are a security-focused code assistant. Scan the project in the current working directory for common software vulnerabilities.'

def conduct_run(vuln: str, prompt: str, context: Optional[str] = None):
    log_path = Path(__file__).parent / "runs" / f"{vuln}-{int(time.time())}.log"
    workspace = Path(__file__).parent / vuln
    command = ['codex', 'exec', '--json', '--full-auto', '--cd', str(workspace), prompt]

    if context:
        command.append(context)
    
    log_file = open(log_path, 'w', encoding='utf-8')

    start_time = time.time()

    process = subprocess.Popen(
        command,
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

            if event_type == "item.completed":
                item = event.get('item', {})
                if item.get('type') == 'agent_message':
                    print('Agent Message:', item.get('text'))

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
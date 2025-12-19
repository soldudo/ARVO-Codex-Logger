import subprocess
import threading
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, TextIO
from queries import get_context

log_lock = threading.Lock()

def log_event(file_handle: TextIO, event_type: str, data: dict):
    """Helper to write standardized JSON logs."""
    entry = {
        "log_type": event_type,
        "timestamp_iso": datetime.now().isoformat(),
        "timestamp_unix": time.time(),
        "data": data
    }
    with log_lock:
        file_handle.write(json.dumps(entry) + '\n')
        file_handle.flush()

# Manualy add context due to db mismatch

vuln_list = [40096184, 42488087, 42513136, 42530547, 424242614]
project_list = ['skia', 'wolfssl', 'binutils-preconditions', 'opensc', 'libxml2']
fuzz_target = [
    '',
    './out/fuzzer-wolfssl-server-randomize tmp/poc', # 42488087
    '',
    '',
    ''
]
crash_list = [
    '',
    'Heap-buffer-overflow WRITE 1', # 42488087
    '',
    '',
    ''
]

experiment_no = 1  # Change this index to run different experiments
vuln = f'arvo-{vuln_list[experiment_no]}-vul'
project = project_list[experiment_no]
crash_type = crash_list[experiment_no]


crash_path = Path(__file__).parent / vuln / "crash_report.log"
try:
    with open(crash_path, "r", encoding="utf-8") as f:
        crash_log = f.read()
except FileNotFoundError:
    print(f"Error: The file {crash_path} was not found.")

workspace_list = [
    '',
    f'{vuln}/src/wolfssl', # 42488087
    '',
    '',
    ''
]

workspace = Path(__file__).parent / workspace_list[experiment_no]

prompt = f'Find and fix the bug in {project} to remove the {crash_type} shown in the log below. Provide the lines of code and file locations changed in this task.\n{crash_log}\n'

prompt1_fail = f'Your previous fix did not remove the crash. Review the new crash log'

def output_listener(process, log_file):
    """
    Background thread: continuously reads, parses, and logs tool output.
    """
    try:
        for line in process.stdout:
            line = line.rstrip('\n')
            if not line.strip(): continue

            try:
                event = json.loads(line)                
                log_event(log_file, "tool_event", event)

                # 3. Console Display Logic (Human Readable)
                msg_type = event.get('type')
                
                # --- CASE A: Item Started (e.g., Starting a command) ---
                if msg_type == 'item.started':
                    item = event.get('item', {})
                    if item.get('type') == 'command_execution':
                        print(f"\n> Executing: {item.get('command')}")

                # --- CASE B: Item Completed (e.g., Reasoning or Command Output) ---
                elif msg_type == 'item.completed':
                    item = event.get('item', {})
                    
                    if item.get('type') == 'reasoning':
                        # Clean up bold markdown for console if desired
                        text = item.get('text', '').replace('**', '')
                        print(f"\n[AI Thinking]: {text}")
                        
                    elif item.get('type') == 'command_execution':
                        output = item.get('aggregated_output', '(no output)')
                        exit_code = item.get('exit_code')
                        
                        # Truncate huge outputs for console readability
                        display_output = output
                        if len(output) > 500:
                            display_output = output[:500] + "\n...[Output Truncated]..."
                            
                        print(f"[Result (Exit {exit_code})]:\n{display_output}")

                # --- CASE C: Turn Completed (The "Ready" Signal) ---
                elif msg_type == 'turn.completed':
                    usage = event.get('usage', {})
                    in_tok = usage.get('input_tokens', 0)
                    out_tok = usage.get('output_tokens', 0)
                    print(f"\n--- Turn Complete (Tokens: {in_tok} in / {out_tok} out) ---")
                    print("Waiting for user input...")

                # --- CASE D: Standard Messages ---
                elif msg_type == 'message':
                     print(f"\n[Message]: {event.get('content')}")

            except json.JSONDecodeError:
                # Fallback for non-JSON lines
                print(f"[Raw]: {line}")
                log_event(log_file, "tool_raw_output", {"text": line})

    except Exception as e:
        print(f"\nReader thread error: {e}")
        # Log the crash so you know why logging stopped
        log_event(log_file, "internal_error", {"error": str(e)})

def run_continuous_session(vuln: str, start_prompt: str):
    timestamp = int(time.time())
    log_path = Path(__file__).parent / "runs" / f"{vuln}-{timestamp}" / f"{vuln}-{timestamp}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Starting Continuous Session. Logging to: {log_path}")

    with open(log_path, 'w', encoding='utf-8') as log_file:
        
        command = ['codex', 'exec', '--json', '--cd', str(workspace), start_prompt]
        command_resume = ['codex', 'exec', 'resume', '--last', '--json', '--cd', str(workspace), prompt1_fail]

        log_event(log_file, "session_start", {"command": command})

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE, 
            text=True,
            bufsize=1 
        )

        # 2. Start the Listener Thread
        # This will run in background handling logs while we wait for user input below
        listener = threading.Thread(target=output_listener, args=(process, log_file))
        listener.daemon = True # Ensure thread dies if main program dies
        listener.start()

        # 3. Main Interaction Loop (User Input)
        try:
            print("\n--- Session Started (Type '/quit' to exit) ---")
            while process.poll() is None:
                # Wait for user input
                # Note: This blocks the main thread, but listener thread keeps logging!
                user_feedback = input("\n> ")

                if user_feedback.strip().lower() == '/quit':
                    print("Terminating session...")
                    break

                if not user_feedback.strip():
                    continue

                # Log the User's Input
                log_event(log_file, "user_input", {"content": user_feedback})

                # Send Input to Tool
                # We must add a newline \n so the tool knows the line is finished
                try:
                    process.stdin.write(user_feedback + "\n")
                    process.stdin.flush()
                except BrokenPipeError:
                    print("Error: Tool process is no longer accepting input.")
                    break

        except KeyboardInterrupt:
            print("\nUser interrupted session.")
        
        finally:
            # Cleanup
            process.terminate()
            log_event(log_file, "session_end", {"exit_code": process.poll()})
            print("Session closed.")

if __name__ == "__main__":
    run_continuous_session(vuln, prompt)

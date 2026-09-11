import json
import logging
import re
import sqlite3
from pathlib import Path
from queries import _get_experiment_id_by_tag
from schema import PATCH_VERIFICATION_DDL, PATCH_VERIFICATION_INDEX_DDL

logger = logging.getLogger(__name__)

DB_PATH = 'arvo_loc_runs.db'
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    cursor = conn.cursor()
    try:
        # table for experiment setup
        cursor.execute('''CREATE TABLE IF NOT EXISTS experiments (
            experiment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_tag TEXT UNIQUE NOT NULL,
            description TEXT,
            prompt_template TEXT,
            markdown_json TEXT
        )''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                experiment_id INTEGER REFERENCES experiments(experiment_id),
                       
                run_mode TEXT NOT NULL,
                       
                vuln_id INTEGER NOT NULL,
                timestamp TEXT,
                agent TEXT,
                agent_model TEXT,
                       
                prompt TEXT,
                       
                result TEXT,
                result_json TEXT,
                agent_thought_log TEXT,
                agent_insight_log TEXT,
                duration INTEGER,
                total_cost_usd REAL,
                num_turns INTEGER,
                input_total_tokens INTEGER,
                output_tokens INTEGER,
                total_tokens INTEGER,
                input_tokens INTEGER,
                       
                input_from_cache_tokens INTEGER,
                input_written_to_cache_tokens INTEGER,
                usage_dict TEXT,
                model_usage_dict TEXT,
                result_type TEXT,
                result_error_flag BOOLEAN,
                stop_reason TEXT,
                return_code INTEGER,
                session_id TEXT,
                command TEXT,
                agent_log TEXT,
                caro_log TEXT,
                FOREIGN KEY (vuln_id) REFERENCES arvo(localId)
            )
        ''')

        # Table for agent messages during run
        cursor.execute('''CREATE TABLE IF NOT EXISTS run_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            event_num INTEGER,
            event_type TEXT,
            event_text TEXT,
            event_usage TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        )''')

        # table for patch info and results
        cursor.execute('''CREATE TABLE IF NOT EXISTS patch_data (
            run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
            loc_source TEXT,
            is_crash_resolved BOOLEAN,
            patch_crash_log TEXT,
            compile_errors TEXT
        )''')

        # table for patch verification attempts (diff_tools.py)
        cursor.execute(PATCH_VERIFICATION_DDL)
        cursor.execute(PATCH_VERIFICATION_INDEX_DDL)

        conn.commit()
    finally:
        cursor.close()
        conn.close()

def parse_agent_run(run_path: Path):
    run_id = run_path.parent.name
    session_start = agent_output = session_end = None
    logger.debug(f'run_path: {run_path} exists: {run_path.exists()} is file: {run_path.is_file()}')

    if not run_path.exists() or not run_path.is_file():
        raise FileNotFoundError(f'The log file at {run_path} does not exist.')
    
    logger.info(f'Parsing run log at {run_path}')
    with run_path.open('r', encoding='utf-8') as run_file:
        agent_log = run_file.read()
        run_file.seek(0)
        for raw_line in run_file:
            if not raw_line.strip():
                continue
            
            try:
                line = json.loads(raw_line)
            except json.JSONDecodeError:
                logger.error(f'Error parsing line as JSON. Skipping.')
                continue

            log_type = line.get('log_type')
            # stream_output only needed for early runs and can phase out
            if log_type in ("agent_output", "stream_output"):
                agent_output = line
            elif log_type == "session_start":
                session_start = line
            elif log_type == "session_end":
                session_end = line

    if not agent_output:
        logger.critical(f'CRITICAL: agent log not found in run log. Exiting.')
        raise ValueError(f'CRITICAL: agent log not found in run log. Exiting.')

    run_mode = session_start.get('run_mode')

    experiment_tag = session_start.get('experiment_tag')
    experiment_id = None
    if experiment_tag:
        experiment_id = _get_experiment_id_by_tag(experiment_tag)
        if not experiment_id:
            logger.warning(f"Experiment tag '{experiment_tag}' not found. Inserting run without ID.")

    vuln_id = session_start.get('vuln')

    prompt = session_start.get('prompt')

    loc_run_id = session_start.get('loc_run_id')

    # timestamp_unix = int(session_start.get('timestamp_unix'))
    timestamp_iso = session_start.get('timestamp_iso')
    duration = int(session_end.get('duration_seconds', 0))
    command_list = session_start.get('command')
    # patch_url = session_start.get('patch_url')
    return_code = session_end.get('return_code')

    # agent log is a list of json dicts
    agent_trace = agent_output.get('data', [])

    # running agent message narrative stored in this list
    assistant_event_list = []
    agent_insight_list = []
    agent_thought_list = []
    todo_list = []
    result_json = {}

    pattern = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL)

    agent_turn = 1
    agent_model = ''

    logger.info('Parsing agent trace..')
    for event in agent_trace:
        # reset content_str after each event is parsed to protect integrity of next event
        content_str = ''
        logger.debug(f'Handling #{agent_turn} event: {event.get('type')}')
        match event.get('type'):
            
            case 'assistant':
                content = event.get('message').get('content')[0]
                content_type = content.get('type')
                logger.debug(f'content_type: {content_type}')

                match content_type:
                    case 'thinking':
                        content_str = content.get('thinking')
                        logger.debug(f'thinking str: {content_str}')

                    case 'text':
                        content_str = content.get('text')
                        logger.debug(f'text str: {content_str}')
                        if content_str.startswith('`★ Insight'):
                            agent_insight_list.append(content_str)
                        match = pattern.search(content_str)
                        if match:
                            json_str = match.group(1)
                            try:
                                result_json = json.loads(json_str)
                            except json.JSONDecodeError as e:
                                logger.error(f'Failed to parse JSON block: {e}')


                        elif content_str.startswith('[THOUGHT]'):
                            agent_thought_list.append(content_str)

                    case 'tool_use':
                        bash_input = content.get('input')

                        if content.get('name') == 'Bash':
                            content_str = f'command: {bash_input.get('command')} \ndescription: {bash_input.get('description')}'
                            logger.debug(f'bash str: {content_str}')

                        # overwrites todo_list with latest state if its a list
                        elif content.get('name') == 'TodoWrite':
                            input_todo_list = bash_input.get('todos')
                            logger.debug(f'todo encountered: {input_todo_list}')
                            if isinstance(input_todo_list, list):
                                todo_list = input_todo_list

                # handle data that needs to update after each assistant event
                # if tool_use is Todo list or Read, do not add to narrative
                if content_type != 'tool_use' or content.get('name') not in ('TodoWrite', 'Read'):
                    assistant_event = {
                        'turn': agent_turn,
                        'type': content_type,
                        'text': content_str,
                        'usage': event.get('message', {}).get('usage', {})
                    }
                    logger.debug(f'adding to event list: {json.dumps(assistant_event)}')
                    # add content to agent narrative list
                    assistant_event_list.append(assistant_event)
                    agent_turn += 1

            # cases below should only update once each run
            case 'system':
                logger.debug('Processing system event')
                session_id = event.get('session_id')
                if not agent_model:
                    agent_model = event.get('model')

            case 'result':
                result_type = event.get('subtype')
                result_error_flag = event.get('is_error')

                total_cost_usd = event.get('total_cost_usd')
                duration_ms = event.get('duration_ms')
                duration_api_ms = event.get('duration_api_ms')
                num_turns = event.get('num_turns')
                result = event.get('result')
                stop_reason = event.get('stop_reason')

                usage_dict = event.get('usage', {})
                input_tokens = usage_dict.get('input_tokens')
                input_from_cache_tokens = usage_dict.get('cache_read_input_tokens')
                input_written_to_cache_tokens = usage_dict.get('cache_creation_input_tokens')
                input_total_tokens = input_tokens + input_from_cache_tokens + input_written_to_cache_tokens
                output_tokens = usage_dict.get('output_tokens')
                total_tokens = input_total_tokens + output_tokens

                cache_creation_dict = usage_dict.get('cache_creation', {})
                ephemeral_1h_input_tokens = cache_creation_dict.get('ephemeral_1h_input_tokens')
                ephemeral_5m_input_tokens = cache_creation_dict.get('ephemeral_5m_input_tokens')
                
                # dict of model dicts
                model_usage_dict = event.get('modelUsage', {})

    agent_insight_log = '\n---\n'.join(agent_insight_list)
    agent_thought_log = '\n---\n'.join(agent_thought_list)
    vuln_list = result_json.get('vulnerabilities', [])
    vuln_count = len(vuln_list)
    command = " ".join(command_list)

    # Send data to database

    try:
        init_db()

        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON") 
        cursor = conn.cursor()
        placeholders = ", ".join(["?"] * 30)
        cursor.execute(f'''
            INSERT INTO runs (
                run_id, run_mode, experiment_id,
                vuln_id, timestamp, agent, agent_model, prompt,
                result, result_json, agent_thought_log, agent_insight_log, duration,
                total_cost_usd, num_turns, input_total_tokens, output_tokens, total_tokens,
                input_tokens, input_from_cache_tokens, input_written_to_cache_tokens, usage_dict, model_usage_dict,
                result_type, result_error_flag, stop_reason, return_code, session_id,
                command, agent_log
            ) VALUES ({placeholders})
        ''', (
            run_id, run_mode, experiment_id,
            vuln_id, timestamp_iso, 'claude', agent_model, prompt,
            result, json.dumps(result_json), agent_thought_log, agent_insight_log, duration,
            total_cost_usd, num_turns, input_total_tokens, output_tokens, total_tokens,
            input_tokens, input_from_cache_tokens, input_written_to_cache_tokens, json.dumps(usage_dict) if usage_dict else None, json.dumps(model_usage_dict) if model_usage_dict else None,
            result_type, result_error_flag, stop_reason, return_code, session_id,
            command, agent_log
        ))

        # cursor.execute('''
        #     ALTER TABLE runs ADD COLUMN run_mode TEXT NOT NULL DEFAULT 'loc'
        #     CHECK (run_type IN ('loc', 'patch'));
        # ''')
        
        

        for event in assistant_event_list:
            cursor.execute('''
                INSERT INTO run_events (run_id, event_num, event_type, event_text, event_usage)
                VALUES (?, ?, ?, ?, ?)
            ''', (run_id, event.get('turn'), event.get('type'), event.get('text'), json.dumps(event.get('usage', {}))))

        if run_mode == 'patch':
            cursor.execute(f'''
                INSERT INTO patch_data (run_id, loc_source)
                    VALUES (?, ?)
            ''', (run_id, loc_run_id))

        conn.commit()
            
    except sqlite3.IntegrityError as e:
        logger.error(f"DB Error: {e}")

    finally:
        cursor.close()
        conn.close()

# Run this file directly & uncomment parse_agent_run to manually parse a run specified below
if __name__ == '__main__':
    logging.basicConfig(
        filename='run_parser.log', 
        level=logging.DEBUG,             
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Script started directly.")
    trace_file = Path('runs/arvo-435781342-vul1772638872/agent_arvo-435781342-vul1772638872.log')
    
    # parse_agent_run(trace_file)
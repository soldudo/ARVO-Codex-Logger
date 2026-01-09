import sqlite3
import logging

from schema import ContentType, CrashLogType, RunRecord

logger = logging.getLogger(__name__)

DB_PATH = 'arvo_experiments.db'
# WARNING: 
    # ARVO's crash output field is sometimes truncated ie 42513136
    # Recommend manually fuzzing using command: arvo
def get_context(id: int) -> tuple:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT project, crash_type, patch_url FROM arvo WHERE localId = ?', (id,))
        context = cursor.fetchone()
        if context:
            return context
        else:
            return None, None, None
    finally:
        cursor.close()
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                vuln_id INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                workspace_relative TEXT,
                patch_url TEXT,
                prompt TEXT,
                duration REAL,
                input_tokens INTEGER,
                cached_input_tokens INTEGER,
                output_tokens INTEGER,
                total_tokens INTEGER,
                agent TEXT,
                agent_model TEXT,
                resume_flag BOOLEAN,
                resume_id TEXT,
                agent_log TEXT,
                agent_reasoning TEXT,
                crash_log_original TEXT,
                crash_log_patch TEXT,
                crash_resolved BOOLEAN,                
                caro_log TEXT,
                FOREIGN KEY (vuln_id) REFERENCES arvo(localId)
            )
        ''')

        # Table for File Changes (One-to-Many relationship with runs)
        cursor.execute('''CREATE TABLE IF NOT EXISTS implicated_files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            file_path TEXT,
            original_content TEXT,
            patched_content TEXT,
            ground_truth_content TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        )''')
        conn.commit()
    finally:
        cursor.close()
        conn.close()


# add agent_log
def record_run(run_data: RunRecord):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO runs (
                run_id, vuln_id, workspace_relative, patch_url,
                prompt, duration, input_tokens, cached_input_tokens,
                output_tokens, total_tokens, agent, agent_model,
                resume_flag, resume_id, agent_log, agent_reasoning
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_data.run_id, run_data.vuln_id, run_data.workspace_relative,
            run_data.patch_url, run_data.prompt, run_data.duration, run_data.input_tokens,
            run_data.cached_input_tokens, run_data.output_tokens, run_data.total_tokens,
            run_data.agent, run_data.agent_model, run_data.resume_flag, 
            run_data.resume_id, run_data.agent_log, run_data.agent_reasoning
        ))
        for filepath in run_data.modified_files_relative:
            cursor.execute('''
                INSERT INTO implicated_files (run_id, file_path)
                VALUES (?, ?)
            ''', (run_data.run_id, filepath))

        conn.commit()
    except sqlite3.IntegrityError as e:
        logger.error(f"Error: run_id {run_data.run_id} already exits in db: {e}")

    finally:
        cursor.close()
        conn.close()

def insert_content(run_id:str, file_path:str, kind: ContentType, content: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    col_map = {
        ContentType.ORIGINAL: "original_content",
        ContentType.PATCHED: "patched_content",
        ContentType.GROUND_TRUTH: "ground_truth_content"
    }

    target_col = col_map.get(kind)
    if not target_col:
        logger.error(f"Invalid content type: {kind}")
        raise ValueError(f"Invalid content type: {kind}")
    
    try:
        query = f'''
            UPDATE implicated_files
            SET {target_col} = ?
            WHERE run_id = ? AND file_path = ?
        '''
        cursor.execute(query, (content, run_id, file_path))

        if cursor.rowcount == 0:
            logger.error(f"Warning: No record found for {file_path} in run {run_id}. Content not saved.")
        else:
            logger.info(f"Updated {target_col} for {file_path}")

        conn.commit()
    finally:
        cursor.close()
        conn.close()

def insert_crash_log(run_id: str, kind: CrashLogType, crash_log: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    col_map = {
        CrashLogType.ORIGINAL: "crash_log_original",
        CrashLogType.PATCH: "crash_log_patch"
    }

    target_col = col_map.get(kind)
    if not target_col:
        logger.error(f"Invalid crash log type: {kind}")
        raise ValueError(f"Invalid crash log type: {kind}")
    
    try:
        query = f'''
            UPDATE runs
            SET {target_col} = ?
            WHERE run_id = ?
        '''
        cursor.execute(query, (crash_log, run_id))

        if cursor.rowcount == 0:
            logger.error(f"Warning: No run found with ID {run_id}. Crash log not saved.")
        else:
            logger.info(f"Updated {target_col} for run {run_id}")

        conn.commit()
    except sqlite3.IntegrityError as e:
        logger.error(f"Database error for run_id {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()

def update_agent_log(run_id: str, agent_log_path: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    try:
        with open(agent_log_path, 'r', encoding='utf-8') as file:
            log_content = file.read()
    except FileNotFoundError:
        logger.error(f"Error: The file {agent_log_path} was not found.")
        return
    try:
        query = f'''
            UPDATE runs
            SET agent_log = ?
            WHERE run_id = ?
        '''
        cursor.execute(query, (log_content, run_id))

        if cursor.rowcount == 0:
            logger.error(f"Warning: No run found with ID {run_id}. Agent log not saved.")
        else:
            logger.info(f"Updated agent_log for run {run_id}")

        conn.commit()
    except sqlite3.IntegrityError as e:
        logger.error(f"Database error for run_id {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()

def update_caro_log(run_id: str, caro_log_path: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    try:
        with open(caro_log_path, 'r', encoding='utf-8') as file:
            log_content = file.read()
    except FileNotFoundError:
        logger.error(f"Error: The file {caro_log_path} was not found.")
        return
    try:
        query = f'''
            UPDATE runs
            SET caro_log = ?
            WHERE run_id = ?
        '''
        cursor.execute(query, (log_content, run_id))

        if cursor.rowcount == 0:
            logger.error(f"Warning: No run found with ID {run_id}. Caro log not saved.")
        else:
            logger.info(f"Updated caro_log for run {run_id}")

        conn.commit()
    except sqlite3.IntegrityError as e:
        logger.error(f"Database error for run_id {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()

def update_crash_resolved(run_id: str, resolved: bool):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE runs
            SET crash_resolved = ?
            WHERE run_id = ?
        ''', (resolved, run_id))

        if cursor.rowcount == 0:
            logger.error(f"Warning: No run found with ID {run_id}. Crash resolved status not updated.")
        else:
            logger.info(f"Updated crash_resolved for run {run_id} to {resolved}")

        conn.commit()
    finally:
        cursor.close()
        conn.close()

import sqlite3
import logging
from typing import Optional
from schema import ContentType, CrashLogType, RunRecord

logger = logging.getLogger(__name__)

DB_PATH = 'arvo_experiments.db'

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

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

# TODO: change init to include on delete cascade
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
        cursor.execute('''CREATE TABLE IF NOT EXISTS run_files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            file_path TEXT,
            patched_content TEXT,
            original_file_id INTEGER,
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS original_files (
            original_file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            original_content TEXT,
            ground_truth_content TEXT,
            FOREIGN KEY (vuln_id) REFERENCES arvo(localId)
            UNIQUE(vuln_id, file_path)
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
                INSERT INTO run_files (run_id, file_path)
                VALUES (?, ?)
            ''', (run_data.run_id, filepath))
            cursor.execute('''
                INSERT OR IGNORE INTO original_files (vuln_id, file_path)
                VALUES (?, ?)
            ''', (run_data.vuln_id, filepath))
            #
            cursor.execute("""
                SELECT original_file_id FROM original_files 
                WHERE vuln_id = ? AND file_path = ?
            """, (run_data.vuln_id, filepath))
    
            result = cursor.fetchone()
            if not result:
                logger.error(f'Error: Could not retrieve original_file_id')
            original_file_id = result[0]

            # Step 4: Link the run to this original file
            cursor.execute("""
                UPDATE run_files
                SET original_file_id = ?
                WHERE run_id = ? AND file_path = ?
            """, (original_file_id, run_data.run_id, filepath))
            
            if cursor.rowcount == 0:
                logger.warning(f"Could not link original file. No entry in run_files for {filepath}")

        conn.commit()
    except sqlite3.IntegrityError as e:
        logger.error(f"Error: run_id {run_data.run_id} already exits in db: {e}")

    finally:
        cursor.close()
        conn.close()

# This has been separated into three functions and updated to new db schema
# def insert_content(run_id:str, file_path:str, kind: ContentType, content: str):
#     conn = sqlite3.connect(DB_PATH)
#     conn.execute("PRAGMA foreign_keys = ON")

#     try:
#         if kind == ContentType.PATCHED:
#             _update_patched_


#     if not target_col:
#         logger.error(f"Invalid content type: {kind}")
#         raise ValueError(f"Invalid content type: {kind}")
    
#     try:
#         logger.info(f'Updating... \nrun: {run_id}\npath: {file_path}')
#         query = f'''
#             UPDATE run_files
#             SET {target_col} = ?
#             WHERE run_id = ? AND file_path = ?
#         '''
#         cursor.execute(query, (content, run_id, file_path))

#         if cursor.rowcount == 0:
#             logger.error(f"Warning: No record found for {file_path} in run {run_id}. Content not saved.")
#         else:
#             logger.info(f"Updated {target_col} for {file_path}")

#         conn.commit()
#     finally:
#         cursor.close()
#         conn.close()

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

def get_crash_log(run_id: str, kind: CrashLogType = CrashLogType.PATCH, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    col_map = {
        CrashLogType.ORIGINAL: "crash_log_original",
        CrashLogType.PATCH: "crash_log_patch"
    }
    target_col = col_map.get(kind)
    if not target_col:
        logger.error(f"Invalid crash log type: {kind}")
        raise ValueError(f"Invalid crash log type: {kind}")

    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        cursor = conn.execute(f'SELECT {target_col} FROM runs WHERE run_id = ?', (run_id,))
        row = cursor.fetchone()
        if row is None:
            logger.warning(f'WARNING: No run found with id: {run_id}')
            return None
        return row[0]
    except sqlite3.Error as e:
        logger.error(f'db error retrieving {target_col} for {run_id}')
        return None
    finally:
        if should_close:
            conn.close()

def get_resume_id(run_id: str, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        cursor = conn.execute(f'SELECT resume_id FROM runs WHERE run_id = ?', (run_id,))
        row = cursor.fetchone()
        if row is None:
            logger.warning(f'WARNING: No run found with id: {run_id}')
            return None
        return row[0]
    except sqlite3.Error as e:
        logger.error(f'db error retrieving resume_id for {run_id}')
        return None
    finally:
        if should_close:
            conn.close()

def get_agent_log(run_id: str):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        cursor = conn.execute('SELECT agent_log FROM runs WHERE run_id = ?', (run_id,))
        row = cursor.fetchone()
        if row is None:
            logger.warning(f'WARNING: No run found with id: {run_id}')
            return None
        return row[0]
    except sqlite3.Error as e:
        logger.error(f'db error retrieving resume_id for {run_id}')
        return None
    finally:
        if should_close:
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

def update_crash_resolved(run_id: str, resolved: bool, conn: Optional[sqlite3.Connection] = None):
    # 1. Determine if we own the connection (and thus should close it)
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        with conn:
            cursor = conn.execute('''
                UPDATE runs
                SET crash_resolved = ?
                WHERE run_id = ?
            ''', (resolved, run_id))
            if cursor.rowcount == 0:
                logger.error(f"Warning: No run found with ID {run_id}. Crash resolved status not updated.")
            else:
                logger.info(f"Updated crash_resolved for run {run_id} to {resolved}")
    except sqlite3.Error as e:
        logging.error(f"Database error updating run {run_id}: {e}")
        # Note: 'with conn' automatically rolled back changes if an error occurred inside it.
        
    finally:
        # 3. Only close the connection if we created it locally
        if should_close:
            conn.close()

def update_patch(run_id: int, file_path: str, content: str, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        with conn:
            cursor = conn.execute('''
                UPDATE run_files
                SET patched_content = ?
                WHERE run_id = ? AND file_path = ?
            ''', (content, run_id, file_path))
            if cursor.rowcount == 0:
                logger.error(f"Warning: No record found for {file_path} in run {run_id}. Content not saved.")
            else:
                logger.info(f"Updated run {run_id} patched file: {file_path}")
    except sqlite3.Error as e:
        logging.error(f"Database error updating run_id {run_id} patched file: {file_path}: {e}")
        
    finally:
        if should_close:
            conn.close()

def update_original(vuln_id: int, file_path: str, content: str, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        query = '''
                UPDATE original_files
                SET original_content = ?
                WHERE vuln_id = ? AND file_path = ? AND original_content IS NULL
            '''
        if should_close:
            with conn:
                cursor = conn.execute(query, (content, vuln_id, file_path))
        else:
            cursor = conn.execute(query, (content, vuln_id, file_path))

        if cursor.rowcount > 0:
            logger.info(f"Updated vulnerability {vuln_id} original file: {file_path}")
        else:
            check_cur = conn.execute(
                "SELECT 1 FROM original_files WHERE vuln_id = ? AND file_path = ?",
            )
            if check_cur.fetchone():
                logger.info(f"Skipped update: {file_path} (Vuln {vuln_id}) already has content.")
            else:
                logger.warning(f"Warning: Row missing for {file_path} (Vuln {vuln_id}). Cannot update.")
                
    except sqlite3.Error as e:
        logging.error(f"Database error updating vuln {vuln_id} original file: {file_path}: {e}")
        
    finally:
        if should_close:
            conn.close()

def update_ground_truth(vuln_id: int, file_path: str, content: str, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        query = '''
                UPDATE original_files
                SET ground_truth_content = ?
                WHERE vuln_id = ? AND file_path = ? AND ground_truth_content IS NULL
            '''
        if should_close:
            with conn:
                cursor = conn.execute(query, (content, vuln_id, file_path))
        else:
            cursor = conn.execute(query, (content, vuln_id, file_path))
        
        if cursor.rowcount > 0:
            logger.info(f"Updated vulnerability {vuln_id} ground_truth file: {file_path}")
        else:
            check_cur = conn.execute(
                "SELECT 1 FROM original_files WHERE vuln_id = ? AND file_path = ?",
            )
            if check_cur.fetchone():
                logger.info(f"Skipped update: {file_path} (Vuln {vuln_id}) already has content.")
            else:
                logger.warning(f"Warning: Row missing for {file_path} (Vuln {vuln_id}). Cannot update.")

           
    except sqlite3.Error as e:
        logging.error(f"Database error updating vuln {vuln_id} ground_truth file: {file_path}: {e}")
        
    finally:
        if should_close:
            conn.close()

def remove_run(run_id: str, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        with conn:
            conn.execute('DELETE FROM implicated_files WHERE run_id = ?', (run_id,))
            conn.execute('DELETE FROM runs WHERE run_id = ?', (run_id,))
            logging.info(f'Successfully deleted {run_id} from db.')
    
    except sqlite3.Error as e:
        logging.error(f'Error during {run_id} deletion: {e}')
    
    finally:
        if should_close:
            conn.close()

# if __name__ == "__main__":

    # experiment_run = 'arvo-40096184-vul-1767674103'
    # remove_run(experiment_run)


    # with open('./crash_log_patch.log', 'r', encoding='utf-8') as f:
    #     crash_log = f.read()
    # insert_crash_log(experiment_run, CrashLogType.PATCH, crash_log)
    # update_crash_resolved(experiment_run, True)
    # with open('./crash_log_original.log', 'r', encoding='utf-8') as f:
    #     crash_log = f.read()
    # insert_crash_log(experiment_run, CrashLogType.ORIGINAL, crash_log)

    # conn = sqlite3.connect(DB_PATH)
    # cursor = conn.cursor()
    # cursor.execute('DELETE FROM implicated_files where run_id = ?', (experiment_run,))

    # conn.commit()
    # cursor.close()
    # conn.close()
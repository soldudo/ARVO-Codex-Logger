import sqlite3
import logging
import json
from typing import Optional, Dict, Any
from schema import CrashLogType, LegacyRunRecord

logger = logging.getLogger(__name__)

DB_PATH = 'arvo_loc_runs.db'

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def get_all_runs_data(columns: str, conn: Optional[sqlite3.Connection] = None) -> Optional[list[tuple]]:
    """
    Fetches specified columns for all records in the runs table.
    Expects a comma-separated string of column names.
    """
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        # Note: As with your other helper, ensure 'columns' is strictly 
        # controlled internally to prevent SQL injection.
        cursor = conn.execute(f'SELECT {columns} FROM runs')
        rows = cursor.fetchall()
        
        if not rows:
            logger.warning(f'WARNING: No data found in the runs table.')
            return []
            
        return rows

    except sqlite3.Error as e:
        logger.error(f'DB error retrieving {columns} for all runs: {e}')
        return None
    finally:
        if should_close:
            conn.close()

def _get_experiment_id_by_tag(experiment_tag: str, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        cursor = conn.execute(
            "SELECT experiment_id FROM experiments WHERE experiment_tag = ?", 
            (experiment_tag,)
        )
        row = cursor.fetchone()
        return row[0] if row else None
    except sqlite3.Error as e:
        logger.error(f'DB error looking up tag {experiment_tag}: {e}')
        return None
    finally:
        if should_close:
            conn.close()

def _fetch_experiment_data(experiment_tag: str, columns: str, conn: Optional[sqlite3.Connection] = None) -> Optional[tuple]:
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        experiment_id = _get_experiment_id_by_tag(experiment_tag, conn)
        if experiment_id is None:
            logger.error(f'Experiment tag {experiment_tag} not found in db.')
            return []
        safe_columns = ", ".join(columns) if isinstance(columns, list) else columns
        cursor = conn.execute(f'SELECT {safe_columns} FROM experiments WHERE experiment_id = ?', (experiment_id,))
        data = cursor.fetchall()
        return data
    
    except sqlite3.Error as e:
        logger.error(f'DB error retrieving {columns} for {experiment_tag}: {e}')
        return None
    except Exception as e:
        logger.error(f'Unexpected error processing {experiment_tag}: {e}')
        return None
    finally:
        if should_close:
            conn.close()

def _fetch_run_data(run_id: str, columns: str, conn: Optional[sqlite3.Connection] = None) -> Optional[tuple]:
    """
    Helper function to manage connections and fetch specific columns for a run_id.
    """
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        # Note: 'columns' is provided internally by our own functions, 
        # so using an f-string here is safe from SQL injection.
        cursor = conn.execute(f'SELECT {columns} FROM runs WHERE run_id = ?', (run_id,))
        row = cursor.fetchone()
        
        if row is None:
            logger.warning(f'WARNING: No run found for run_id: {run_id} (Columns: {columns})')
            return None
            
        return row

    except sqlite3.Error as e:
        logger.error(f'DB error retrieving {columns} for {run_id}: {e}')
        return None
    finally:
        if should_close:
            conn.close()

def _update_run(run_id: str, updates: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> bool:
    # updates: A dictionary of column names and their new values (e.g., {'experiment_tag': 'discrete-loc-patch-pairs-fullmd', 'prompt': 'continue'}).
    # Returns bool: True if the update was successful and affected at least one row, False otherwise.

    if not updates:
        logger.warning(f"No update data provided for run_id: {run_id}")
        return False

    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        set_clause = ', '.join([f"{col} = ?" for col in updates.keys()])
        
        values = list(updates.values())
        values.append(run_id) 

        # 3. Execute and Commit
        query = f"UPDATE runs SET {set_clause} WHERE run_id = ?"
        cursor = conn.execute(query, values)
        
        # CRITICAL: Committing the transaction saves it to the database
        conn.commit() 

        # Check if any rows were actually updated
        if cursor.rowcount == 0:
            logger.warning(f'WARNING: No run found to update for run_id: {run_id}')
            return False
            
        return True

    except sqlite3.Error as e:
        logger.error(f'DB error updating {run_id}. Data: {updates}. Error: {e}')
        # Roll back any partial changes if an error occurs
        if conn:
            conn.rollback() 
        return False
        
    finally:
        if should_close:
            conn.close()

def _update_patch_data(run_id: str, updates: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> bool:
    # updates: A dictionary of column names and their new values (e.g., {'experiment_tag': 'discrete-loc-patch-pairs-fullmd', 'prompt': 'continue'}).
    # Returns bool: True if the update was successful and affected at least one row, False otherwise.

    if not updates:
        logger.warning(f"No patch_data provided for run_id: {run_id}")
        return False

    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        set_clause = ', '.join([f"{col} = ?" for col in updates.keys()])
        
        values = list(updates.values())
        values.append(run_id) 

        # 3. Execute and Commit
        query = f"UPDATE patch_data SET {set_clause} WHERE run_id = ?"
        cursor = conn.execute(query, values)
        
        # CRITICAL: Committing the transaction saves it to the database
        conn.commit() 

        # Check if any rows were actually updated
        if cursor.rowcount == 0:
            logger.warning(f'WARNING: No run found to update for run_id: {run_id}')
            return False
            
        return True

    except sqlite3.Error as e:
        logger.error(f'DB error updating {run_id}. Data: {updates}. Error: {e}')
        # Roll back any partial changes if an error occurs
        if conn:
            conn.rollback() 
        return False
        
    finally:
        if should_close:
            conn.close()

def _update_experiment(experiment_id: int, updates: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> bool:
    if not updates:
        logger.warning(f"No update data provided for experiment_id: {experiment_id}")
        return False

    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        set_clause = ', '.join([f"{col} = ?" for col in updates.keys()])
        
        values = list(updates.values())
        values.append(experiment_id) 

        # 3. Execute and Commit
        query = f"UPDATE experiments SET {set_clause} WHERE experiment_id = ?"
        cursor = conn.execute(query, values)
        
        # CRITICAL: Committing the transaction saves it to the database
        conn.commit() 

        # Check if any rows were actually updated
        if cursor.rowcount == 0:
            logger.warning(f'WARNING: No experiment found to update for experiment_id: {experiment_id}')
            return False
            
        return True

    except sqlite3.Error as e:
        logger.error(f'DB error updating {experiment_id}. Data: {updates}. Error: {e}')
        # Roll back any partial changes if an error occurs
        if conn:
            conn.rollback() 
        return False
        
    finally:
        if should_close:
            conn.close()

def insert_experiment(experiment_tag, description, prompt_template, markdown_json, conn: Optional[sqlite3.Connection] = None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    
    try:
        cursor = conn.execute(f'''
            INSERT into experiments(
                experiment_tag, description, prompt_template, markdown_json
            ) VALUES (?, ?, ?, ?)
        ''', (
            experiment_tag, description, prompt_template, markdown_json
        ))
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error inserting experiment: {e}")

    finally:
        cursor.close()
        conn.close()

def get_experiment_artifacts(experiment_tag: str, conn: Optional[sqlite3.Connection] = None):
    try:
        rows = _fetch_experiment_data(experiment_tag, 'prompt_template, markdown_json', conn)
        if not rows:
            logger.error(f'No data found for experiment type {experiment_tag}')
            return None
        prompts_str, markdowns_str = rows[0]
        # 3. Parse Dictionary 1 (Parameters)
        prompts_dict = {}
        if prompts_str:
            try:
                prompts_dict = json.loads(prompts_str)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse prompt_templates JSON for experiment type {experiment_tag}: {e}")

        # 4. Parse Dictionary 2 (Metrics)
        markdowns_dict = {}
        if markdowns_str:
            try:
                markdowns_dict = json.loads(markdowns_str)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse markdowns JSON for experiment type {experiment_tag}: {e}")

        # 5. Return both (they will be empty {} if they were NULL or corrupted)
        return prompts_dict, markdowns_dict
        
    except Exception as e:
        logger.error(f"Unexpected error retrieving artifacts for experiment type {experiment_tag}: {e}")
        return None

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

def get_vuln_id(run_id: str, conn: Optional[sqlite3.Connection] = None):
    return _fetch_run_data(run_id, 'vuln_id', conn)

def get_result_json(run_id: str, conn: Optional[sqlite3.Connection] = None):
    return _fetch_run_data(run_id, 'result_json, vuln_id', conn)

def get_original_crash_log(arvo_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT crash_output FROM arvo WHERE localId = ?', (arvo_id,))
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            return None
    finally:
        cursor.close()
        conn.close()


def get_resume_id(run_id: str, conn: Optional[sqlite3.Connection] = None):
    return _fetch_run_data(run_id, 'resume_id', conn)


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

def get_agent_trace(run_id: str, conn: Optional[sqlite3.Connection]=None):
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = '''
        SELECT crash_resolved, agent_log
        FROM runs
        WHERE run_id = ?
        '''
        cursor.execute(query, (run_id,))
        row = cursor.fetchone()

        if not row:
            logger.error(f'Run {run_id} not found in db')
            return None
        
        crash_resolved = row['crash_resolved']
        logger.info(f'crash_res: {crash_resolved}')
        agent_log = row['agent_log']
        resolution_str = 'SUCCESS' if crash_resolved else 'FAILURE'

        trace_lines = []
    
        for line in agent_log.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)

                item = entry.get('data', {}).get('item', {})
                item_type = item.get('type')

                if item_type == 'reasoning':
                    text = item.get('text', '').replace('\n', ' ').strip()
                    trace_lines.append(f'[THOUGHT] {text}')

                elif item_type == 'command_execution':
                    cmd = item.get('command', '').strip()
                    trace_lines.append(f'[CMD] {cmd}')
                    
            except json.JSONDecodeError:
                continue
        
        trace_block = (
            f'[METADATA]\n'
            f'Run ID: {run_id}\n'
            f'Result: {resolution_str}\n\n'
            f'[TRACE]\n' + '\n'.join(trace_lines)
        )
        return trace_block
    
    except sqlite3.Error as e:
        logger.error(f'db error retrieving agent_log for {run_id}: {e}')
        return None
    finally:
        if should_close:
            conn.close() 

def update_run_experiment_by_tag(run_id: str, experiment_tag: str, conn: Optional[sqlite3.Connection] = None):
    experiment_id = _get_experiment_id_by_tag(experiment_tag, conn)
    if not experiment_id:
        logger.warning(f"Experiment tag '{experiment_tag}' not found.")
        return False
    return _update_run(run_id, {'experiment_id': experiment_id}, conn)   

def update_patch_crash_results(run_id: str, is_crash_resolved: bool, patch_crash_log: str, compile_errors: str, conn: Optional[sqlite3.Connection] = None):
    return _update_patch_data(run_id, {'is_crash_resolved': is_crash_resolved, 'patch_crash_log': patch_crash_log, 'compile_errors': compile_errors}, conn)


# --- patch_verification -----------------------------------------------------
# One row per verification attempt. Unlike _update_patch_data, which is
# UPDATE-only and relies on run_parser.py pre-creating every patch_data row,
# these own their INSERT.

def get_fuzz_target(arvo_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[str]:
    """The fuzz target this vuln's POC exercises, for the verification transcript."""
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        row = conn.execute('SELECT fuzz_target FROM arvo WHERE localId = ?',
                           (arvo_id,)).fetchone()
        return row[0] if row else None
    except sqlite3.Error as e:
        logger.error(f'DB error retrieving fuzz_target for {arvo_id}: {e}')
        return None
    finally:
        if should_close:
            conn.close()


def start_patch_verification(run_id: str, conn: Optional[sqlite3.Connection] = None,
                             **provenance):
    """Open a verification attempt. Returns (verification_id, attempt), or
    (None, None) on failure.

    attempt is MAX(attempt)+1 for the run, so re-verifying never overwrites an
    earlier verdict. Accepts any patch_verification column as a keyword.
    """
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        row = conn.execute(
            'SELECT COALESCE(MAX(attempt), 0) + 1 FROM patch_verification WHERE run_id = ?',
            (run_id,)).fetchone()
        attempt = row[0] if row else 1

        cols = ['run_id', 'attempt'] + list(provenance.keys())
        vals = [run_id, attempt] + list(provenance.values())
        placeholders = ', '.join('?' for _ in cols)
        cursor = conn.execute(
            f'INSERT INTO patch_verification ({", ".join(cols)}) VALUES ({placeholders})',
            vals)
        conn.commit()
        logger.info(f'Opened verification attempt {attempt} for {run_id} '
                    f'(verification_id={cursor.lastrowid})')
        return cursor.lastrowid, attempt

    except sqlite3.Error as e:
        logger.error(f'DB error opening verification for {run_id}: {e}')
        conn.rollback()
        return None, None
    finally:
        if should_close:
            conn.close()


def update_patch_verification(verification_id: int, updates: Dict[str, Any],
                              conn: Optional[sqlite3.Connection] = None) -> bool:
    """Write one stage's results. Called after each stage so a run that dies
    part-way still leaves the stages that completed."""
    if not updates:
        logger.warning(f'No verification data provided for {verification_id}')
        return False

    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        set_clause = ', '.join(f'{col} = ?' for col in updates.keys())
        values = list(updates.values()) + [verification_id]
        cursor = conn.execute(
            f'UPDATE patch_verification SET {set_clause} WHERE verification_id = ?',
            values)
        conn.commit()

        if cursor.rowcount == 0:
            logger.warning(f'No verification row found for id {verification_id}')
            return False
        return True

    except sqlite3.Error as e:
        logger.error(f'DB error updating verification {verification_id}. '
                     f'Columns: {list(updates)}. Error: {e}')
        conn.rollback()
        return False
    finally:
        if should_close:
            conn.close()


def get_patch_verification(run_id: str, attempt: Optional[int] = None,
                           conn: Optional[sqlite3.Connection] = None):
    """Latest attempt for a run, or a specific one. Returns sqlite3.Row."""
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True

    try:
        conn.row_factory = sqlite3.Row
        if attempt is None:
            return conn.execute(
                'SELECT * FROM patch_verification WHERE run_id = ? '
                'ORDER BY attempt DESC LIMIT 1', (run_id,)).fetchone()
        return conn.execute(
            'SELECT * FROM patch_verification WHERE run_id = ? AND attempt = ?',
            (run_id, attempt)).fetchone()
    except sqlite3.Error as e:
        logger.error(f'DB error reading verification for {run_id}: {e}')
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

import pytest
import os
import sqlite3
from enum import Enum
from unittest.mock import MagicMock, patch
from queries import get_context, get_crash_log
from schema import CrashLogType

@pytest.fixture
def mock_db():
    """
    Creates a temporary in-memory SQLite database for testing.
    This avoids creating real files and ensures a clean state for every test.
    """
    conn = sqlite3.connect(':memory:')
    
    # create the table expected by the function
    conn.execute('''
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            crash_log_original BLOB,
            crash_log_patch BLOB
        )
    ''')
    
    yield conn
    conn.close()

DB_PATH = 'arvo_experiments.db'

def insert_crash_log(run_id: str, kind: CrashLogType, crash_log: str):
    conn = sqlite3.connect('test_db.db')
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    col_map = {
        CrashLogType.ORIGINAL: "crash_log_original",
        CrashLogType.PATCH: "crash_log_patch"
    }

    target_col = col_map.get(kind)
    if not target_col:
        raise ValueError(f"Invalid crash log type: {kind}")
    
    try:
        query = f'''
            UPDATE runs
            SET {target_col} = ?
            WHERE run_id = ?
        '''
        cursor.execute(query, (crash_log, run_id))

        if cursor.rowcount == 0:
            print(f"Warning: No run found with ID {run_id}. Crash log not saved.")
        else:
            print(f"Updated {target_col} for run {run_id}")

        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"Database error for run_id {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()

@pytest.mark.skipif(not os.path.exists(DB_PATH), reason="Local arvo_experiments.db not present")
# db integration test
def test_get_context():
    arvo_id = 42488087
    project, crash_type, patch_url = get_context(arvo_id)
    assert project == 'wolfssl'
    assert crash_type == 'Heap-buffer-overflow WRITE 1'
    assert patch_url == 'https://github.com/wolfssl/wolfssl/commit/4364700c01bb55bc664106e6c8b997849ec69228'



def test_insert_crash_log():
    test_run_id = 'test_run_123'
    test_crash_log = 'This is a test crash log.'
    insert_crash_log(run_id=test_run_id, kind=CrashLogType.PATCH, crash_log=test_crash_log)

    # Verify insertion by querying the database directly
    import sqlite3
    conn = sqlite3.connect('test_db.db')
    cursor = conn.cursor()
    cursor.execute('SELECT crash_log_patch FROM runs WHERE run_id = ?', (test_run_id,))
    result = cursor.fetchone()
    conn.close()

    assert result is not None
    assert result[0] == test_crash_log

def test_get_crash_log_patch(mock_db):
    """Test retrieving the PATCH log successfully."""
    # 1. Setup: Insert dummy data
    run_id = "run-123"
    expected_content = b"Binary Patch Data"
    mock_db.execute(
        "INSERT INTO runs (run_id, crash_log_patch) VALUES (?, ?)", 
        (run_id, expected_content)
    )
    mock_db.commit()

    # 2. Action: Call the function with our test DB connection
    result = get_crash_log(run_id, kind=CrashLogType.PATCH, conn=mock_db)

    # 3. Assertion: Verify we got the correct data back
    assert result == expected_content

def test_get_crash_log_success_original(mock_db):
    """Test retrieving the ORIGINAL log successfully."""
    run_id = "run-456"
    expected_content = b"Original Source Code"
    mock_db.execute(
        "INSERT INTO runs (run_id, crash_log_original) VALUES (?, ?)", 
        (run_id, expected_content)
    )
    
    result = get_crash_log(run_id, kind=CrashLogType.ORIGINAL, conn=mock_db)
    assert result == expected_content

def test_get_crash_log_not_found(mock_db):
    """Test that querying a non-existent ID returns None."""
    result = get_crash_log("ghost-id", kind=CrashLogType.PATCH, conn=mock_db)
    assert result is None

def test_get_crash_log_invalid_type(mock_db):
    """Test that passing an unmapped Enum type raises ValueError."""
    class FakeEnum(Enum):
        BROKEN = 99

    with pytest.raises(ValueError, match="Invalid crash log type"):
        get_crash_log("run-123", kind=FakeEnum.BROKEN, conn=mock_db)

@patch('queries._get_connection')
def test_get_crash_log_manages_internal_connection(mock_get_conn):
    """
    Test that if NO connection is passed, the function:
    1. Creates one using _get_connection
    2. Queries the DB
    3. Closes the connection automatically
    """
    # Setup Mocks
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    
    # Configure the mock chain: conn.execute -> returns cursor -> cursor.fetchone -> returns data
    mock_get_conn.return_value = mock_conn
    mock_conn.execute.return_value = mock_cursor
    mock_cursor.fetchone.return_value = (b'Internal Data',)

    # Action: Call WITHOUT passing a 'conn' argument
    result = get_crash_log("run-123", kind=CrashLogType.PATCH)

    # Assertions
    assert result == b'Internal Data'
    mock_get_conn.assert_called_once()      # It should have asked for a new connection
    mock_conn.close.assert_called_once()    # It should have closed it at the end

def test_get_crash_log_db_error_handling(mock_db, caplog):
    """
    Test that database errors are caught and logged without crashing.
    Uses 'caplog' to verify the logger output.
    """
    # Force a DB error by closing the connection before the query runs
    mock_db.close()

    result = get_crash_log("run-123", kind=CrashLogType.PATCH, conn=mock_db)

    # It should handle the error gracefully and return None
    assert result is None
    
    # Check that it logged the error
    assert "Database error retrieving crash log" in caplog.text
    
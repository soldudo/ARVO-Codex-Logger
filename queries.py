import sqlite3

def get_context(id: int) -> tuple:
    conn = sqlite3.connect('arvo.db')
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT project, crash_type, crash_output FROM arvo WHERE localId = ?', (id,))
        context = cursor.fetchone()
        if context:
            return context
        else:
            return None, None
    finally:
        cursor.close()
        conn.close()
    
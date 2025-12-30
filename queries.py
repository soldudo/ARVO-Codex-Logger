import sqlite3
# WARNING: 
    # ARVO's crash output field is sometimes truncated ie 42513136
    # Recommend manually fuzzing using command: arvo
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
    
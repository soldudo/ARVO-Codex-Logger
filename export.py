import csv
import sqlite3

DB_PATH = 'arvo_experiments.db'

def export_runs():
    columns = [
        'run_id', 'vuln_id', 'timestamp', 'patch_url', 'duration', 'input_tokens', 'cached_input_tokens',
        'output_tokens', 'total_tokens', 'agent', 'agent_model', 'resume_flag', 'agent_reasoning', 'crash_resolved'
        ]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cols_formatted = ', '.join(columns)

    try:
        cursor.execute(f'SELECT {cols_formatted} FROM runs')
        rows = cursor.fetchall()

        with open('caro_runs.csv', 'w', newline='', encoding='utf-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(columns)  # Write header
            csvwriter.writerows(rows)         # Write data rows

        print("Exported runs to caro_runs.csv")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    export_runs()
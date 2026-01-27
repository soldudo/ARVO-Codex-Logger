import difflib
import json
import logging
import sys
import pandas as pd
import sqlite3
from typing import List
from queries import get_agent_log, get_agent_trace

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("analysis.log", mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
DB_PATH = 'arvo_experiments.db'


def get_all_logs_bulk():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Select only the columns you strictly need
    cursor.execute("SELECT run_id, agent_log FROM runs")
    
    results = {}
    
    # fetchall() pulls everything into memory at once
    for run_id, log_str in cursor.fetchall():
        # SQLite stores JSON as a string, so we must parse it
        results[run_id] = json.loads(log_str)
        
    conn.close()
    return results


def summarize_run_types():
    conn = sqlite3.connect(DB_PATH)
    
    # 1. Fetch the raw log text. 
    # We cannot use json_extract in SQL because the column contains multiple JSON objects.
    query = "SELECT run_id, agent_log FROM runs"
    
    # Use a generator or chunking if the DB is massive to avoid MemoryErrors
    # For simplicity, we load it into a DataFrame iterator here
    df_iterator = pd.read_sql_query(query, conn, chunksize=1000)
    
    counts = []

    for chunk in df_iterator:
        for index, row in chunk.iterrows():
            run_id = row['run_id']
            log_blob = row['agent_log']
            
            # 2. Parse the JSON Lines manually
            if not log_blob: continue

            # Split by newline to separate the stacked JSON objects
            for line in log_blob.split('\n'):
                if not line.strip(): continue # Skip empty lines
                
                try:
                    entry = json.loads(line)
                    
                    # SAFETY CHECK 1: Ensure entry is actually a dictionary
                    if not isinstance(entry, dict):
                        continue

                    # 3. Apply your filters in Python
                    # SAFETY CHECK 2: Extract 'data', ensuring it's not None
                    data_obj = entry.get("data")
                    
                    # SAFETY CHECK 3: Ensure 'data' is a dictionary before accessing 'type'
                    if isinstance(data_obj, dict):
                        if data_obj.get("type") == "item.completed":
                            # Safely extract the nested item type
                            item = data_obj.get("item")
                            if isinstance(item, dict):
                                item_type = item.get("type")
                                if item_type:
                                    counts.append({'run_id': run_id, 'item_type': item_type})
                            
                except json.JSONDecodeError:
                    continue # Skip corrupt lines

    conn.close()

    # 4. Create the summary DataFrame
    if not counts:
        return pd.DataFrame()
        
    df_counts = pd.DataFrame(counts)
    
    summary = df_counts.pivot_table(
        index='run_id', 
        columns='item_type', 
        aggfunc='size', 
        fill_value=0
    )
    
    return summary

def collect_traces(run_list: List[str]):
    conn = sqlite3.connect(DB_PATH)
    traces = []
    traces_txt = "./traces.txt"
    for run in run_list:
        traces.append(get_agent_trace(run_id=run, conn=conn))
    try:
        with open(traces_txt, 'w', encoding='utf-8') as f:
            for trace in traces:
                f.write(trace)
                f.write("\n\n" + "="*40 + "\n\n")
    except IOError as e:
        print(f'Error writing traces: {e}')
    
run_list = ['arvo-424242614-vul-1768536270',
            'arvo-42529030-vul-1768028888',
            'arvo-42531212-vul-1768546958',
            'arvo-42531212-vul-1768452053',
            'arvo-42528951-vul-1768029561',
            'arvo-42528951-vul-1768544627']

collect_traces(run_list)

# Usage
# find_bad_json(DB_PATH)

# --- Output Example ---
# item_type  command_execution  reasoning
# run_id                                 
# 101                        5         12
# 102                        8          4

# df = summarize_run_types()

# df.to_csv('df.csv')
# results = get_all_logs_bulk()
# for result in results:


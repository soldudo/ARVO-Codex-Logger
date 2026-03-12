import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import datetime
import random

# --- CONFIGURATION ---
DB_NAME = "arvo_experiments.db"

class RunViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Run Log Inspector")
        self.root.geometry("1200x800")
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Connect to DB
        self.conn = sqlite3.connect(DB_NAME)
        self.cursor = self.conn.cursor()

        # Main Layout: Vertical PanedWindow
        self.paned_window = ttk.PanedWindow(root, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Top Frame: Filter & Treeview
        self.top_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.top_frame, weight=1)

        # Bottom Frame: Details & Logs
        self.bottom_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.bottom_frame, weight=2) # Give more space to logs

        self._init_top_panel()
        self._init_detail_panel()
        self.refresh_data()

    def _init_top_panel(self):
        """Creates the search bar and data table."""
        # --- Toolbar ---
        toolbar = ttk.Frame(self.top_frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Label(toolbar, text="Search Run ID:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<Return>", self.refresh_data)
        
        ttk.Button(toolbar, text="Filter/Refresh", command=self.refresh_data).pack(side=tk.LEFT, padx=5)

        # --- Treeview (Table) ---
        columns = ("run_id", "vuln_id", "timestamp", "duration", "total_tokens", "resolved")
        self.tree = ttk.Treeview(self.top_frame, columns=columns, show="headings", selectmode="browse")
        
        # Define Headings
        self.tree.heading("run_id", text="Run ID")
        self.tree.heading("vuln_id", text="Vuln ID")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("duration", text="Duration (s)")
        self.tree.heading("total_tokens", text="Total Tokens")
        self.tree.heading("resolved", text="Resolved?")

        # Define Column Widths
        self.tree.column("run_id", width=100)
        self.tree.column("vuln_id", width=60)
        self.tree.column("timestamp", width=120)
        self.tree.column("duration", width=80)
        self.tree.column("total_tokens", width=80)
        self.tree.column("resolved", width=70)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.top_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind Selection Event
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

    def _init_detail_panel(self):
        """Creates the tabbed view for logs."""
        self.notebook = ttk.Notebook(self.bottom_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Define tabs and corresponding DB columns
        self.tabs = {
            "Prompt": "prompt",
            "Agent Log": "agent_log",
            "Agent Reasoning": "agent_reasoning",
            "Caro Log": "caro_log",
            "Crash Log (Original)": "crash_log_original",
            "Crash Log (Patch)": "crash_log_patch",
            "Metadata": None # Special handling
        }

        self.text_widgets = {}

        for tab_name, db_col in self.tabs.items():
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab_name)
            
            # Text area with scrollbar
            text_area = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 10)) # Log-friendly font
            v_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_area.yview)
            h_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text_area.xview)
            
            text_area.configure(yscroll=v_scroll.set, xscroll=h_scroll.set)
            
            v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
            text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            self.text_widgets[tab_name] = text_area

    def refresh_data(self, event=None):
        """Fetches summary data for the top table."""
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)

        search_term = f"%{self.search_var.get()}%"
        
        query = """
            SELECT run_id, vuln_id, timestamp, duration, total_tokens, crash_resolved 
            FROM runs 
            WHERE run_id LIKE ? OR vuln_id LIKE ?
            ORDER BY timestamp DESC
        """
        
        try:
            self.cursor.execute(query, (search_term, search_term))
            rows = self.cursor.fetchall()
            
            for row in rows:
                # Color code based on resolution status
                tags = ('success',) if row[5] else ('fail',)
                self.tree.insert("", tk.END, values=row, tags=tags)
            
            # Configure tag colors
            self.tree.tag_configure('success', background="#e6ffe6") # Light green
            self.tree.tag_configure('fail', background="#ffe6e6")    # Light red

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", str(e))

    def on_row_select(self, event):
        """Fetches full details when a row is clicked."""
        selected_item = self.tree.selection()
        if not selected_item:
            return

        item_values = self.tree.item(selected_item[0], "values")
        run_id = item_values[0]

        # Fetch full row
        query = "SELECT * FROM runs WHERE run_id = ?"
        self.cursor.execute(query, (run_id,))
        
        # Get column names to map data correctly
        col_names = [description[0] for description in self.cursor.description]
        row_data = dict(zip(col_names, self.cursor.fetchone()))

        # Update Text Widgets
        for tab_name, db_col in self.tabs.items():
            widget = self.text_widgets[tab_name]
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            
            if tab_name == "Metadata":
                # Create a pretty summary for Metadata tab
                meta_text = ""
                for key, value in row_data.items():
                    if key not in self.tabs.values(): # Exclude large logs we already show elsewhere
                        meta_text += f"{key.ljust(25)}: {value}\n"
                widget.insert(tk.END, meta_text)
            else:
                content = row_data.get(db_col)
                if content:
                    widget.insert(tk.END, str(content))
                else:
                    widget.insert(tk.END, "<No Data>")
            
            widget.config(state=tk.DISABLED) # Make read-only

# --- DUMMY DATA GENERATOR (FOR TESTING) ---
def create_mock_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create Table
    c.execute("""CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, vuln_id INTEGER NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                workspace_relative TEXT, patch_url TEXT, prompt TEXT, duration REAL,
                input_tokens INTEGER, cached_input_tokens INTEGER, output_tokens INTEGER, total_tokens INTEGER,
                agent TEXT, agent_model TEXT, resume_flag BOOLEAN, resume_id TEXT,
                agent_log TEXT, agent_reasoning TEXT, crash_log_original TEXT, crash_log_patch TEXT,
                crash_resolved BOOLEAN, caro_log TEXT, FOREIGN KEY (vuln_id) REFERENCES arvo(localId))""")
    
    # Check if empty
    c.execute("SELECT count(*) FROM runs")
    if c.fetchone()[0] == 0:
        print("Generating mock data...")
        for i in range(20):
            resolved = random.choice([True, False])
            c.execute("""INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (f"RUN-{1000+i}", random.randint(1, 50), datetime.datetime.now(), 
                       "/var/workspace", "http://patch.url", "Fix this bug please.", 
                       random.uniform(10.5, 120.0), 100, 0, 50, 150, "AutoAgent", "GPT-4", 
                       False, None, f"Log entry {i}...\nStep 1: Analyzing...", f"Reasoning {i}...", 
                       "Error: Segfault...", "Clean compilation.", resolved, "Caro initialized."))
        conn.commit()
    conn.close()

# --- MAIN ENTRY POINT ---
if __name__ == "__main__":
    # create_mock_db() # Create file if it doesn't exist
    
    root = tk.Tk()
    app = RunViewerApp(root)
    root.mainloop()
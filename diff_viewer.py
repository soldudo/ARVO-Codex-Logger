import sqlite3
import difflib
import tkinter as tk
from tkinter import ttk

DB_PATH = 'arvo_experiments.db'

class PatchAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Patch Strategy Analyzer")
        self.root.geometry("1200x700") # Wider window for columns

        # --- Top Layout: The Data Grid (Selection) ---
        # We split the screen: Top half for selection, Bottom half for diff
        paned_window = tk.PanedWindow(root, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        top_frame = tk.Frame(paned_window)
        bottom_frame = tk.Frame(paned_window)
        
        paned_window.add(top_frame, height=300)
        paned_window.add(bottom_frame)

        # --- Treeview Configuration ---
        columns = ("run_id", "project", "vuln_id", "crash", "file_path")
        self.tree = ttk.Treeview(top_frame, columns=columns, show="headings")
        
        headers = {
            'run_id': ('Run ID', 60),
            "project": ("Project", 100),
            "vuln_id": ("Vuln ID", 100),
            "crash": ("Crash Type", 150),
            "file_path": ("Filepath", 200)
        }

        for col, (text, width) in headers.items():
            self.tree.column(col, width=width, anchor="center" if "id" in col else "w")
            self.tree.heading(
                col,
                text=text,
                command=lambda c=col: self.sort_column(c, False)
            )

        # Add scrollbar to Treeview
        tree_scroll = ttk.Scrollbar(top_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind Click Event
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        # --- Bottom Layout: The Diff Viewer ---
        self.text_area = tk.Text(bottom_frame, font=("Consolas", 10))
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Configure Colors
        self.text_area.tag_config("added", background="#e6ffec", foreground="#006400")
        self.text_area.tag_config("removed", background="#ffebe9", foreground="#a60000")
        self.text_area.tag_config("info", foreground="#888888")

        self.conn = sqlite3.connect(DB_PATH)
        self.populate_table()

    def sort_column(self, col, reverse):
        """
        Sorts the treeview contents when a column header is clicked.
        col: The column identifier
        reverse: True for descending, False for ascending
        """
        # Retrieve all items in the tree as (value, item_id) tuples
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        
        # Attempt to convert to numbers for correct numeric sorting
        # (Otherwise "10" comes before "2")
        try:
            l.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            # Fallback to string sorting if data isn't numeric
            l.sort(reverse=reverse)

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        # Update the heading command to reverse the sort order next time
        self.tree.heading(
            col, 
            command=lambda: self.sort_column(col, not reverse)
        )
        
    def populate_table(self):
        cursor = self.conn.cursor()
        # NOTE: Adjust table/column names to match your actual schema
        query = """
            SELECT 
                f.run_id, 
                v.project, 
                v.localId, 
                v.crash_type, 
                f.file_path 
            FROM run_files f
            JOIN runs r ON f.run_id = r.run_id
            JOIN arvo v ON r.vuln_id = v.localId
        """
        try:
            cursor.execute(query)
            for row in cursor.fetchall():
                # Insert row into Treeview
                # iid (Item ID) is set to a composite key "run_id|filename" for easy retrieval
                unique_id = f"{row[0]}|{row[4]}"
                self.tree.insert("", tk.END, iid=unique_id, values=row)
        except sqlite3.OperationalError as e:
            print(f"Database Error: {e}")

    def on_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        # We stored "run_id|filename" as the row ID (iid)
        unique_id = selected_items[0]
        try:
            run_id, file_path = unique_id.split("|")
            self.show_diff(run_id, file_path)
        except ValueError:
            pass

    def show_diff(self, run_id, file_path):
        cursor = self.conn.cursor()
        query = '''
            SELECT
                of.original_content,
                f.patched_content
            FROM run_files f
            JOIN original_files of
                ON f.original_file_id = of.original_file_id
            WHERE f.run_id = ? AND f.file_path = ?
        '''

        try:
            cursor.execute(query, (run_id, file_path))
            row = cursor.fetchone()
        
            self.text_area.delete(1.0, tk.END)
        
            if row:
                orig, patched = row
                orig_lines = (orig or "").splitlines()
                patch_lines = (patched or "").splitlines()
                
                diff = difflib.unified_diff(
                    orig_lines, patch_lines, 
                    fromfile=f"Original ({file_path})", 
                    tofile=f"Patched (Run {run_id})"
                )
                
                for line in diff:
                    tag = "info" if line.startswith(('---', '+++', '@@')) else \
                        "added" if line.startswith('+') else \
                        "removed" if line.startswith('-') else None
                    self.text_area.insert(tk.END, line + "\n", tag)
            else:
                self.text_area.insert(tk.END, 'Content not found for this selection.')
        except sqlite3.Error as e:
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, f'Database Error: {e}')

if __name__ == "__main__":
    root = tk.Tk()
    app = PatchAnalyzer(root)
    root.mainloop()
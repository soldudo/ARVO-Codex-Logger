import tkinter as tk
from tkinter import ttk
import re
import sqlite3
import json

DB_PATH = 'arvo_loc_runs.db'

class NarrativeViewer(tk.Tk):
    def __init__(self, db_path):
        super().__init__()
        self.title("Narrative Viewer")
        self.geometry("1000x700")
        self.db_path = db_path
        
        # In-memory storage for the currently selected session's events
        self.current_events = []
        
        self.setup_ui()
        self.setup_text_tags()
        self.load_run_gallery()

    def setup_ui(self):
        # --- Left Panel: Session Gallery ---
        left_frame = ttk.Frame(self, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        ttk.Label(left_frame, text="Runs", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.run_list = tk.Listbox(left_frame, width=30)
        self.run_list.pack(fill=tk.BOTH, expand=True)
        self.run_list.bind('<<ListboxSelect>>', self.on_run_select)

        # --- Right Panel: Filters and Log Viewer ---
        right_frame = ttk.Frame(self)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Filters
        filter_frame = ttk.Frame(right_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.show_text = tk.BooleanVar(value=True)
        self.show_thinking = tk.BooleanVar(value=False) 
        self.show_tools = tk.BooleanVar(value=False)

        ttk.Checkbutton(filter_frame, text="Text", variable=self.show_text, command=self.render_log).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Thinking", variable=self.show_thinking, command=self.render_log).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Tools", variable=self.show_tools, command=self.render_log).pack(side=tk.LEFT, padx=5)

        # Log Text Widget
        self.log_display = tk.Text(right_frame, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 10))
        self.log_display.pack(fill=tk.BOTH, expand=True)

    # def setup_text_tags(self):
    #     # This is Tkinter's version of CSS!
    #     self.log_display.tag_configure("turn_header", font=("Consolas", 11, "bold"), foreground="blue", spacing1=10)
    #     self.log_display.tag_configure("thinking", foreground="gray", font=("Consolas", 10, "italic"))
    #     self.log_display.tag_configure("text", foreground="black")
    #     self.log_display.tag_configure("tool_use", foreground="green", background="#f0f0f0")

    def setup_text_tags(self):
        # 1. Turn Header: Bold, dark slate, with extra space above it to separate turns
        self.log_display.tag_configure(
            "turn_header", 
            font=("Segoe UI", 12, "bold"), 
            foreground="#2C3E50", 
            spacing1=8,  # Space above
            spacing3=5    # Space below
        )
        
        self.log_display.tag_configure(
            "text", 
            font=("Segoe UI", 11), 
            foreground="#333333", 
            lmargin1=10, 
            lmargin2=10,
            spacing1=5,
            spacing3=5
        )
        
        self.log_display.tag_configure(
            "thinking", 
            font=("Segoe UI", 10, "italic"), 
            foreground="#7F8C8D", 
            lmargin1=40,
            lmargin2=40,
            spacing1=5,
            spacing3=5
        )
        
        self.log_display.tag_configure(
            "tool_use", 
            font=("Consolas", 10), 
            foreground="#A9B7C6",  
            background="#2B2B2B",  
            lmargin1=10, 
            lmargin2=10,
            spacing1=5,
            spacing3=5
        )

    def load_run_gallery(self):
        # Query your SQLite DB for unique sessions
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT run_id FROM run_events")
        for row in cursor.fetchall():
            self.run_list.insert(tk.END, row[0])
        conn.close()

    def on_run_select(self, event):
        selection = self.run_list.curselection()
        if not selection: return
        
        run_id = self.run_list.get(selection[0])
        
        # Load all events for this run into memory
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT event_num, event_type, event_text FROM run_events WHERE run_id = ? ORDER BY event_num", (run_id,))
        self.current_events = cursor.fetchall()
        conn.close()
        
        self.render_log() # Draw the UI based on current checkboxes

    def render_log(self):
        target_turn = None

        # Check if the text widget actually has content
        if self.log_display.index("end-1c") != "1.0": 
            # Get the index of the character currently at the top-left corner
            top_index = self.log_display.index("@0,0")
            
            # Search backwards to find which Turn header we are currently under
            header_idx = self.log_display.search("▶", top_index, backwards=True, stopindex="1.0")
            
            # If we didn't find one above, we are at the very top. Look down instead.
            if not header_idx:
                header_idx = self.log_display.search("▶", "1.0", stopindex=tk.END)
                
            if header_idx:
                # Grab the text of that header (e.g., "▶ 5 | TEXT")
                header_text = self.log_display.get(header_idx, f"{header_idx} lineend")
                
                # Extract just the turn number using regex
                match = re.search(r"▶ (\d+)", header_text)
                if match:
                    target_turn = match.group(1)

        self.log_display.config(state=tk.NORMAL)
        self.log_display.delete(1.0, tk.END) # Clear the screen
        
        for turn, c_type, body in self.current_events:
            # Check if user wants to see this type
            if c_type == 'text' and not self.show_text.get(): continue
            if c_type == 'thinking' and not self.show_thinking.get(): continue
            if c_type == 'tool_use' and not self.show_tools.get(): continue
            
            # Insert the header and content with specific color tags
            self.log_display.insert(tk.END, f"▶ {turn} [{c_type}]\n", "turn_header")
            if c_type == 'tool_use':
                self.log_display.insert(tk.END, f"\n{body.strip()}\n\n", c_type)
            else:
                self.log_display.insert(tk.END, f"{body.strip()}\n", c_type)
            
        self.log_display.config(state=tk.DISABLED) # Make read-only again

        if target_turn:                    
                    # Search the newly built text for the turn we were looking at
                    new_idx = self.log_display.search(f"▶ {target_turn}", "1.0", stopindex=tk.END)
                    if new_idx:
                        # yview snaps the widget so that this specific line is at the top of the view
                        self.log_display.yview(new_idx)

if __name__ == "__main__":
    app = NarrativeViewer(DB_PATH)
    app.mainloop()
    pass
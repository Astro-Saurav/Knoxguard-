import json
import webbrowser
import pyperclip
import threading
import queue
import customtkinter as ctk
from tkinter import messagebox
from url_scanner import URLScanner
from process_scanner import ProcessScanner

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class ToolTip(ctk.CTkToplevel): # Unchanged
    def __init__(self, widget, text):
        super().__init__()
        self.withdraw(); self.overrideredirect(True)
        self.label = ctk.CTkLabel(self, text=text, fg_color=("gray75", "gray20"), corner_radius=5, padx=8, pady=4); self.label.pack()
        widget.bind("<Enter>", self.show); widget.bind("<Leave>", self.hide)
    def show(self, event): self.geometry(f"+{event.x_root + 15}+{event.y_root + 10}"); self.deiconify()
    def hide(self, event): self.withdraw()

class App(ctk.CTk):
    def __init__(self, url_scanner, process_scanner):
        super().__init__()
        self.title("Security Dashboard"); self.geometry("900x600")
        self.url_scanner = url_scanner; self.process_scanner = process_scanner
        self.process_scan_queue = queue.Queue(); self.last_clipboard = ""
        self.process_widgets = {}

        self.grid_columnconfigure((0, 1), weight=1, uniform="group1")
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(self, text="Live Security Dashboard", font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0, columnspan=2, pady=15)

        self.create_url_panel(); self.create_process_panel()

        status_frame = ctk.CTkFrame(self, height=30, fg_color=("gray85", "gray18")); status_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.status_label = ctk.CTkLabel(status_frame, text="  Initializing...", font=ctk.CTkFont(size=12)); self.status_label.pack(side="left", padx=10)

        # --- IMPORTANT: Save cache on exit ---
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.after(500, self.auto_start_tasks)

    def on_closing(self):
        """Handle window close event."""
        self.status_label.configure(text="  Saving cache and closing...")
        self.process_scanner.save_cache() # Save the collected safe hashes
        self.destroy() # Close the application

    def create_url_panel(self): # Unchanged
        panel = ctk.CTkFrame(self); panel.grid(row=1, column=0, padx=(20, 10), pady=(0, 10), sticky="nsew"); panel.grid_rowconfigure(1, weight=1); panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(panel, text="Clipboard URL Events", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, pady=(10, 5))
        self.url_events_frame = ctk.CTkScrollableFrame(panel, fg_color=("gray85", "gray18")); self.url_events_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

    def create_process_panel(self): # Unchanged
        panel = ctk.CTkFrame(self); panel.grid(row=1, column=1, padx=(10, 20), pady=(0, 10), sticky="nsew"); panel.grid_rowconfigure(1, weight=1); panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(panel, text="Running Processes", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, pady=(10, 5))
        self.process_results_frame = ctk.CTkScrollableFrame(panel, fg_color=("gray85", "gray18")); self.process_results_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.process_results_frame.grid_columnconfigure(0, weight=1)
        self.progress_bar = ctk.CTkProgressBar(panel); self.progress_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(5, 10))

    def auto_start_tasks(self): # Unchanged
        self.status_label.configure(text="  System monitoring is ACTIVE"); self.last_clipboard = pyperclip.paste(); self.monitor_clipboard(); self.run_process_scan()

    def monitor_clipboard(self): # Unchanged
        current_clipboard = pyperclip.paste().strip()
        if (current_clipboard != self.last_clipboard and current_clipboard.startswith(('http://', 'https://')) and '.' in current_clipboard[8:] and len(current_clipboard) > 12):
            self.last_clipboard = current_clipboard
            ScanResultWindow(self, current_clipboard, self.url_scanner)
        self.after(1500, self.monitor_clipboard)

    def add_url_event_to_feed(self, url, verdict, color, details): # Unchanged
        event_frame = ctk.CTkFrame(self.url_events_frame, fg_color=color); event_frame.pack(fill="x", pady=4, padx=4)
        ctk.CTkLabel(event_frame, text=verdict, font=ctk.CTkFont(weight="bold")).pack(pady=(5,0))
        ctk.CTkLabel(event_frame, text=url, wraplength=350, font=ctk.CTkFont(size=11)).pack()
        ctk.CTkLabel(event_frame, text=details, font=ctk.CTkFont(size=11)).pack(pady=(0,5)); self.url_events_frame._parent_canvas.yview_moveto(1)

    def run_process_scan(self): # Unchanged
        self.progress_bar.set(0)
        thread = threading.Thread(target=lambda: [self.process_scan_queue.put(update) for update in self.process_scanner.scan_processes()], daemon=True); thread.start()
        self.check_process_scan_queue()

    def check_process_scan_queue(self): # Unchanged
        try:
            update = self.process_scan_queue.get_nowait()
            if update['type'] == 'new_process': self.add_process_to_list(update)
            elif update['type'] == 'progress': self.progress_bar.set(update['current'] / update['total'])
            elif update['type'] == 'result': self.update_process_in_list(update)
        except queue.Empty: pass
        finally: self.after(50, self.check_process_scan_queue)

    def add_process_to_list(self, data): # Unchanged
        pid = data['pid']
        frame = ctk.CTkFrame(self.process_results_frame); frame.pack(fill="x", pady=2, padx=2); frame.grid_columnconfigure(1, weight=1)
        info_label = ctk.CTkLabel(frame, text=f"{pid}: {data['name']}", anchor="w"); info_label.grid(row=0, column=0, padx=5, pady=2, sticky="w")
        if data['path']: ToolTip(frame, data['path'])
        status_label = ctk.CTkLabel(frame, text="Scanning...", text_color="cyan", anchor="e"); status_label.grid(row=0, column=1, padx=5, pady=2, sticky="e")
        self.process_widgets[pid] = {'frame': frame, 'status_label': status_label}

    def update_process_in_list(self, data):
        # --- THIS METHOD IS UPDATED TO HANDLE THE NEW STATUS ---
        pid = data['pid']
        if pid not in self.process_widgets: return
        
        widgets = self.process_widgets[pid]
        status_label = widgets['status_label']
        frame = widgets['frame']
        
        status = data.get('status', 'Unknown')
        details = data.get('details', '')

        if status == 'Harmful':
            status_label.configure(text=details, text_color="orange")
            terminate_btn = ctk.CTkButton(frame, text="Terminate", width=80, fg_color="#D32F2F", hover_color="#B71C1C", command=lambda p=pid, f=frame: self.terminate_and_remove(p, f))
            terminate_btn.grid(row=0, column=2, padx=(5, 10), pady=2)
        elif status == 'Cached Safe': # NEW STATUS
            status_label.configure(text=details, text_color="cyan")
        elif status == 'Safe':
            status_label.configure(text=details, text_color="gray60")
        else: # Error or other status
            status_label.configure(text=details, text_color="yellow")

    def terminate_and_remove(self, pid, frame): # Unchanged
        if messagebox.askyesno("Confirm Termination", f"Are you sure you want to terminate process PID {pid}?"):
            message, status = self.process_scanner.terminate_process(pid)
            if status == "success": messagebox.showinfo("Success", message); frame.destroy()
            else: messagebox.showerror("Error", message)

# The ScanResultWindow class remains completely unchanged.
class ScanResultWindow(ctk.CTkToplevel):
    def __init__(self, master, url, scanner):
        super().__init__(master)
        self.master_app = master; self.url = url; self.scanner = scanner; self.result_queue = queue.Queue()
        self.title("Scanning URL..."); self.geometry("450x250"); self.transient(master); self.grab_set()
        self.grid_columnconfigure(0, weight=1); self.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(self, text=self.url, wraplength=430, font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=10, pady=(10,5), sticky="ew")
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent"); self.status_frame.grid(row=1, column=0, sticky="nsew")
        self.loading_label = ctk.CTkLabel(self.status_frame, text="Scanning...", font=ctk.CTkFont(size=20)); self.loading_label.pack(expand=True)
        self.loading_animation_id = self.start_loading_animation()
        self.result_frame = ctk.CTkFrame(self, fg_color="transparent"); self.result_frame.grid_columnconfigure(0, weight=1)
        self.verdict_label = ctk.CTkLabel(self.result_frame, font=ctk.CTkFont(size=20, weight="bold")); self.verdict_label.grid(row=0, column=0, pady=(20,10))
        self.details_label = ctk.CTkLabel(self.result_frame, font=ctk.CTkFont(size=14)); self.details_label.grid(row=1, column=0, pady=2)
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent"); self.button_frame.grid(row=2, column=0, pady=10)
        self.block_btn = ctk.CTkButton(self.button_frame, text="Block & Close", command=self.destroy); self.block_btn.pack(side="left", padx=10)
        self.allow_btn = ctk.CTkButton(self.button_frame, text="Allow & Open", state="disabled", command=self.allow_and_open); self.allow_btn.pack(side="left", padx=10)
        thread = threading.Thread(target=lambda: self.result_queue.put(self.scanner.scan_url(self.url)), daemon=True); thread.start()
        self.after(100, self.check_queue)
    def check_queue(self):
        try:
            result = self.result_queue.get_nowait()
            if self.loading_animation_id: self.after_cancel(self.loading_animation_id)
            self.status_frame.grid_forget(); self.result_frame.grid(row=1, column=0, sticky="nsew"); self.display_result(result)
        except queue.Empty: self.after(100, self.check_queue)
    def start_loading_animation(self, dot_count=0):
        self.loading_label.configure(text=f"Scanning{'.' * (dot_count % 4)}"); return self.after(500, self.start_loading_animation, dot_count + 1)
    def display_result(self, result):
        self.title("Scan Complete")
        if "error" in result:
            self.verdict_label.configure(text="Scan Error", text_color="yellow"); self.details_label.configure(text=result["error"], wraplength=400)
            self.master_app.add_url_event_to_feed(self.url, "ERROR", ("#FBC02D", "#F9A825"), result["error"]); return
        stats = result.get("stats", {}); malicious = stats.get("malicious", 0); suspicious = stats.get("suspicious", 0); details_text = f"Detections: {malicious} malicious, {suspicious} suspicious"; self.details_label.configure(text=details_text)
        if malicious > 0:
            self.verdict_label.configure(text="UNSAFE", text_color="#E53935"); self.configure(fg_color="#4E3434"); self.allow_btn.configure(state="normal", fg_color="#D32F2F", hover_color="#B71C1C", text="Open Anyways"); self.master_app.add_url_event_to_feed(self.url, "UNSAFE", ("#EF9A9A", "#B71C1C"), details_text)
        elif suspicious > 0:
            self.verdict_label.configure(text="SUSPICIOUS", text_color="#FDD835"); self.configure(fg_color="#4E4A34"); self.allow_btn.configure(state="normal"); self.master_app.add_url_event_to_feed(self.url, "SUSPICIOUS", ("#FFF59D", "#F9A825"), details_text)
        else:
            self.verdict_label.configure(text="SAFE", text_color="#7CB342"); self.configure(fg_color="#344E3B"); self.allow_btn.configure(state="normal", fg_color="#388E3C", hover_color="#2E7D32"); self.master_app.add_url_event_to_feed(self.url, "SAFE", ("#A5D6A7", "#2E7D32"), details_text)
    def allow_and_open(self): webbrowser.open(self.url); self.destroy()

# The main startup logic remains completely unchanged.
if __name__ == "__main__":
    try:
        with open('config.json') as f: api_key = json.load(f).get('api_key')
        if not api_key or api_key == 'YOUR_VIRUSTOTAL_API_KEY_HERE': raise ValueError("API Key not set in config.json")
    except (FileNotFoundError, ValueError) as e: messagebox.showerror("Configuration Error", str(e)); exit()
    app = App(URLScanner(api_key), ProcessScanner(api_key)); app.mainloop()
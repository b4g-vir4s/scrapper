import customtkinter as ctk
import threading
import time
import pandas as pd
from datetime import datetime
from tkinter import messagebox
import core_engine as engine

class CyberPulseApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber-Pulse Pro | Advanced OSINT Dashboard")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")
        
        # --- UI STATE ---
        self.is_running = False
        self.scraped_data = {}

        # --- LAYOUT CONFIG ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(0, weight=1)

        # 1. Sidebar (Scheduling & Auth)
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        ctk.CTkLabel(self.sidebar, text="VAULT ACCESS", font=("Consolas", 14, "bold")).pack(pady=10)
        self.api_entry = ctk.CTkEntry(self.sidebar, placeholder_text="API Token", show="*")
        self.api_entry.pack(pady=5, padx=10)

        ctk.CTkLabel(self.sidebar, text="AUTOMATION", font=("Consolas", 12)).pack(pady=10)
        self.sched_menu = ctk.CTkOptionMenu(self.sidebar, values=["Manual", "Daily Scan", "Weekly Audit"])
        self.sched_menu.pack(pady=5)

        self.thread_sw = ctk.CTkSwitch(self.sidebar, text="Parallel Matrix Mode")
        self.thread_sw.select()
        self.thread_sw.pack(pady=20)

        # 2. Main Dashboard
        self.main_panel = ctk.CTkFrame(self)
        self.main_panel.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # Infiltration Target (URL)
        self.url_box = ctk.CTkEntry(self.main_panel, placeholder_text="https://threat-intel.com/rss", width=600)
        self.url_box.pack(pady=20)

        # Element Selector
        self.sel_frame = ctk.CTkFrame(self.main_panel, fg_color="transparent")
        self.sel_frame.pack()
        self.selectors = {tag: ctk.BooleanVar(value=True) for tag in ["Text", "Links", "Images", "Metadata"]}
        for tag, var in self.selectors.items():
            ctk.CTkCheckBox(self.sel_frame, text=tag, variable=var).pack(side="left", padx=15)

        # Action Core
        self.run_btn = ctk.CTkButton(self.main_panel, text="START INFILTRATION", command=self.dispatch_scrape, fg_color="#006400")
        self.run_btn.pack(pady=10)

        self.progress = ctk.CTkProgressBar(self.main_panel, width=600)
        self.progress.set(0)
        self.progress.pack(pady=5)

        # Visual DOM / Preview / Logs
        self.tabview = ctk.CTkTabview(self.main_panel, width=800, height=400)
        self.tabview.pack(pady=10, fill="both", expand=True)
        self.tabview.add("Data Preview")
        self.tabview.add("Visual DOM Tree")
        self.tabview.add("System Logs")

        self.preview_text = ctk.CTkTextbox(self.tabview.tab("Data Preview"))
        self.preview_text.pack(fill="both", expand=True)
        
        self.log_text = ctk.CTkTextbox(self.tabview.tab("System Logs"))
        self.log_text.pack(fill="both", expand=True)

        # 3. Export Bar
        self.export_frame = ctk.CTkFrame(self.main_panel)
        self.export_frame.pack(pady=15)
        for fmt in ["JSON", "CSV", "Excel"]:
            ctk.CTkButton(self.export_frame, text=f"Export {fmt}", width=100, command=lambda f=fmt: self.export_action(f)).pack(side="left", padx=5)

    # --- LOGIC HANDLERS ---

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n")

    def dispatch_scrape(self):
        url = self.url_box.get()
        if not url: return messagebox.showwarning("Incomplete", "Missing Target URL")
        
        self.run_btn.configure(state="disabled", text="INFILTRATING...")
        self.log(f"Initiating connection to {url}")
        
        threading.Thread(target=self.run_pipeline, args=(url,), daemon=True).start()

    def run_pipeline(self, url):
        # 1. Fetch
        self.progress.set(0.2)
        html, status = engine.fetch_source(url)
        
        if status != 200:
            self.after(0, lambda: self.log(f"ERROR: Received Status {status}"))
            self.after(0, self.reset_ui)
            return

        # 2. Parse & Sanitize
        self.progress.set(0.5)
        flags = {k: v.get() for k, v in self.selectors.items()}
        raw_data = engine.parse_elements(html, flags)
        
        clean_text, indicators = engine.cyber_sanitizer(raw_data.get("text", ""))
        self.scraped_data = {**raw_data, **indicators}

        # 3. Visualization logic (handled as background process)
        cloud = engine.generate_report_viz(clean_text)
        cloud.to_file("intelligence_reports/latest_viz.png")

        # 4. Update UI
        self.after(0, lambda: self.update_preview(clean_text, indicators))
        self.after(0, self.reset_ui)
        self.progress.set(1.0)

    def update_preview(self, text, ind):
        self.preview_text.insert("end", f"--- CYBER INDICATORS FOUND ---\nIPs: {ind['ips']}\nCVEs: {ind['cves']}\n\n--- TEXT PREVIEW ---\n{text[:500]}...")
        self.log("Extraction successful. Report ready.")

    def reset_ui(self):
        self.run_btn.configure(state="normal", text="START INFILTRATION")

    def export_action(self, fmt):
        if not self.scraped_data: return messagebox.showwarning("Empty", "No data to export.")
        df = pd.DataFrame([self.scraped_data])
        path = f"intelligence_reports/report_{int(time.time())}.{fmt.lower() if fmt != 'Excel' else 'xlsx'}"
        
        if fmt == "JSON": df.to_json(path)
        elif fmt == "CSV": df.to_csv(path)
        else: df.to_excel(path)
        
        messagebox.showinfo("Exported", f"Data saved to {path}")

if __name__ == "__main__":
    import os
    os.makedirs("intelligence_reports", exist_ok=True)
    app = CyberPulseApp()
    app.mainloop()
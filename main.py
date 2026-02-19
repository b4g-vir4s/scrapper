import customtkinter as ctk, threading, os, core_engine, ui_formatters
from tkinter import messagebox

class CyberPulseApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber-Pulse Pro | OSINT Threat Intel"); self.geometry("1200x800")
        self.scraped_data = {}; ctk.set_appearance_mode("dark")
        
        # Header & Controls
        header = ctk.CTkFrame(self, fg_color="#1a1a2e").pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(header, text="🛡️ CYBER-PULSE PRO", font=("Consolas", 20, "bold")).pack()
        
        url_f = ctk.CTkFrame(self).pack(fill="x", padx=10, pady=5)
        self.url_box = ctk.CTkEntry(url_f, placeholder_text="Target URL", width=600)
        self.url_box.pack(side="left", padx=5, pady=10)
        
        self.selectors = {t: ctk.BooleanVar(value=True) for t in ["Text", "Links", "Images", "Metadata"]}
        for t, v in self.selectors.items(): ctk.CTkCheckBox(url_f, text=t, variable=v).pack(side="left")

        # Actions & Status
        btn_f = ctk.CTkFrame(self).pack(fill="x", padx=10)
        self.run_btn = ctk.CTkButton(btn_f, text="🚀 START SCAN", command=self.start_scan, fg_color="green")
        self.run_btn.pack(side="left", padx=5)
        self.status = ctk.CTkLabel(btn_f, text="System Ready", text_color="green")
        self.status.pack(side="left", padx=20)
        self.progress = ctk.CTkProgressBar(self, width=1180); self.progress.pack(pady=10); self.progress.set(0)

        # Output Tabs
        self.tabs = ctk.CTkTabview(self); self.tabs.pack(fill="both", expand=True, padx=10)
        for t in ["📊 Intelligence", "📄 Data", "📜 Logs"]: self.tabs.add(t)
        self.t_out = ctk.CTkTextbox(self.tabs.tab("📊 Intelligence")); self.t_out.pack(fill="both", expand=True)
        self.d_out = ctk.CTkTextbox(self.tabs.tab("📄 Data")); self.d_out.pack(fill="both", expand=True)
        self.l_out = ctk.CTkTextbox(self.tabs.tab("📜 Logs")); self.l_out.pack(fill="both", expand=True)

        # Export Footer
        foot = ctk.CTkFrame(self).pack(fill="x", side="bottom", pady=10)
        for f in ["PDF Report", "JSON", "CSV"]:
            ctk.CTkButton(foot, text=f"📥 {f}", width=100, command=lambda x=f: self.export(x)).pack(side="left", padx=5)

    def log(self, m): self.l_out.insert("end", f"> {m}\n"); self.l_out.see("end")

    def start_scan(self):
        url = self.url_box.get().strip()
        if not url: return messagebox.showwarning("Error", "Enter URL")
        self.run_btn.configure(state="disabled"); self.status.configure(text="Scanning...")
        threading.Thread(target=self.worker, args=(url,), daemon=True).start()

    def worker(self, url):
        try:
            self.progress.set(0.3)
            res = core_engine.process_scan(url, {k: v.get() for k, v in self.selectors.items()})
            if res['status'] == 'success':
                self.scraped_data = res; self.progress.set(1.0)
                self.t_out.insert("1.0", ui_formatters.format_threat_report(res['threat_indicators']))
                self.d_out.insert("1.0", ui_formatters.format_data_preview(res['parsed_data']))
                self.status.configure(text="Scan Complete", text_color="green"); self.log(f"Success: {url}")
            else: self.status.configure(text="Failed", text_color="red"); self.log(f"Error: {res['error']}")
        except Exception as e: self.log(f"Critical Error: {e}")
        finally: self.run_btn.configure(state="normal")

    def export(self, fmt):
        if not self.scraped_data: return messagebox.showwarning("Wait", "Scan first")
        path = f"intelligence_reports/scan_{os.getpid()}.txt"
        if core_engine.export_results(self.scraped_data, fmt, path):
            messagebox.showinfo("Saved", f"Exported to {path}")

if __name__ == "__main__":
    os.makedirs("intelligence_reports", exist_ok=True)
    CyberPulseApp()
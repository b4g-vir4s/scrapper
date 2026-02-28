
import re, socket, time, threading, io, warnings, math, random
from datetime import datetime
from urllib.parse import urlparse, urljoin
from functools import reduce
import requests as req
from bs4 import BeautifulSoup
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors as RC
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

warnings.filterwarnings("ignore")
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette ───────────────────────────────────────────────────────────────────
C = {"bg":"#050810","panel":"#080d1a","card":"#0c1220","card2":"#101828",
     "border":"#1a2744","accent":"#00d4ff","accent2":"#7c3aed","green":"#00ff88",
     "red":"#ff3366","orange":"#ff8c00","dim":"#4a5568","muted":"#2d3748",
     "text":"#e2e8f0","textdim":"#718096"}
SEV = {"CRITICAL":"#ff3366","HIGH":"#ff8c00","MEDIUM":"#ffd700",
       "LOW":"#00d4ff","INFO":"#00ff88","SAFE":"#00ff88"}
MALWARE_KW = ["cryptominer","coinhive","keylogger","shellcode","base64_decode",
              "xmrig","minero","deepminer","jsecoin","crypto-loot"]
EXPLOIT_KW = ["sql injection","union select","directory traversal",
              "buffer overflow","remote code execution","rce exploit"]



# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY FUNCTION 1 — fetch_url                                            ║
# ║  PURPOSE : Downloads the target webpage and captures all HTTP metadata  ║
# ║  WHY     : Everything depends on this raw response (headers, HTML, time)║
# ╚══════════════════════════════════════════════════════════════════════════╝
def fetch_url(url, timeout=12):
    hdrs = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122"}
    try:
        t = time.time()
        r = req.get(url, headers=hdrs, timeout=timeout, allow_redirects=True, verify=False)
        return {"ok":True,"status":r.status_code,"headers":dict(r.headers),
                "text":r.text,"final_url":r.url,"elapsed":round(time.time()-t,2)}
    except Exception as e:
        return {"ok":False,"error":str(e)}

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY FUNCTION 2 — parse_page                                           ║
# ║  PURPOSE : Extracts ALL intelligence from raw HTML using BeautifulSoup  ║
# ║  DETECTS : IPs, malware keywords, encoded blobs, links, images, forms   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def parse_page(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    ga   = lambda t,a: [x.get(a,"") for x in soup.find_all(t) if x.get(a)]
    dom  = urlparse(base_url).netloc
    imgs = [{"src": urljoin(base_url,img.get("src","")),
             "alt": img.get("alt","--"),"w":img.get("width","?"),"h":img.get("height","?")}
            for img in soup.find_all("img") if img.get("src")]
    links = ga("a","href")
    enc   = []
    # Only flag properly padded base64 strings (real encoded payloads have = padding)
    # and long percent-encoded sequences — NOT minified JS variable names
    for pat in [r"(?:[A-Za-z0-9+/]{60,}={1,2})",r"(?:%[0-9a-fA-F]{2}){15,}"]:
        enc.extend(re.findall(pat, html)[:3])
    return {
        "title":      soup.title.string.strip() if soup.title else "N/A",
        "text":       soup.get_text(separator="\n",strip=True)[:6000],
        "links":      links,
        "ext_links":  [l for l in links if l.startswith("http") and urlparse(l).netloc!=dom],
        "scripts":    ga("script","src"),
        "iframes":    ga("iframe","src"),
        "forms":      soup.find_all("form"),
        "inputs":     soup.find_all("input"),
        "images":     imgs,
        "meta":       {m.get("name",m.get("property","?")): m.get("content","")
                       for m in soup.find_all("meta") if m.get("content")},
        "comments":   len(re.findall(r'<!--.*?-->',html,re.DOTALL)),
        "ips_found":  list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', html))),
        "malware_kw": [k for k in MALWARE_KW if k.lower() in html.lower()],
        "exploit_kw": [k for k in EXPLOIT_KW if k.lower() in html.lower()],
        "encoded":    enc,
        "urls_in_src":list(set(re.findall(r'https?://[^\s\'"<>)]+',html)))[:40],
        "headings":   [h.get_text(strip=True) for h in soup.find_all(["h1","h2","h3"])[:15]],
    }

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY FUNCTION 3 — run_checks                                           ║
# ║  PURPOSE : Runs all security checks and returns scored threat findings  ║
# ║  METHOD  : Pure functional — uses reduce() to compose 8 check modules   ║
# ║  OUTPUT  : findings list + numeric score (0-100) + threat level string  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def run_checks(url, resp, data):
    pu, dom = urlparse(url), urlparse(url).netloc
    F  = lambda cat,sev,sc,desc,det="": {"cat":cat,"sev":sev,"score":sc,"desc":desc,"detail":det}
    H  = {k.lower():v for k,v in resp["headers"].items()}

    # ── BAND TARGETS ──────────────────────────────────────────────────────
    # Secure sites (google, github):   score < 30  → SAFE / LOW
    # Misconfigured (testphp, old):    score 40-65 → MEDIUM
    # Malicious (eicar, cryptominers): score 85-100→ CRITICAL
    # ──────────────────────────────────────────────────────────────────────

    # 1. TRANSPORT — 12 pts max (only if no HTTPS; secure sites get 0)
    ssl_f = [F("Transport","HIGH",12,"No HTTPS","Upgrade to TLS.")] \
            if pu.scheme!="https" else [F("Transport","INFO",0,"HTTPS active","")]

    # 2. SECURITY HEADERS — max ~22 pts for a site missing everything
    #    Secure sites (google/github) have most headers → score ~0-6 here
    hdr_f = [F("Headers",sev,sc,desc,f"{h} missing") if h not in H
             else F("Headers","INFO",0,f"{h} present",H[h][:80])
             for h,sev,sc,desc in [
                 ("strict-transport-security","MEDIUM",6,"Missing HSTS"),
                 ("content-security-policy","MEDIUM",7,"Missing CSP"),
                 ("x-frame-options","LOW",4,"No X-Frame-Options"),
                 ("x-content-type-options","LOW",3,"No X-Content-Type-Options"),
                 ("referrer-policy","LOW",2,"No Referrer-Policy"),
             ]]
    # Server version disclosure — small informational deduction
    srv = H.get("server","")
    if srv and any(v in srv.lower() for v in ["apache","nginx","iis","php"]):
        hdr_f.append(F("Disclosure","LOW",4,"Server version disclosed",f"Server: {srv}"))
    if H.get("x-powered-by",""):
        hdr_f.append(F("Disclosure","LOW",2,"X-Powered-By exposed",H["x-powered-by"]))

    # 3. FORMS — only genuinely dangerous cases
    form_f = []
    seen_get = False; seen_http_action = False
    for fm in data["forms"]:
        method  = fm.get("method","get").lower()
        action  = fm.get("action","")
        fin     = fm.find_all("input") if hasattr(fm,"find_all") else []
        has_pwd = any(i.get("type","").lower()=="password" for i in fin)
        if method=="get" and has_pwd and not seen_get:
            form_f.append(F("Forms","MEDIUM",8,"Login form uses GET","Credentials in URL."))
            seen_get = True
        if action.startswith("http://") and not seen_http_action:
            form_f.append(F("Forms","MEDIUM",10,"Form posts to plain HTTP",action[:80]))
            seen_http_action = True

    # 4. EXTERNAL SCRIPTS — trusted CDNs are fine; unknown third-parties score low
    TRUSTED = {"ajax.googleapis.com","cdnjs.cloudflare.com","cdn.jsdelivr.net",
               "code.jquery.com","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com",
               "unpkg.com","fonts.googleapis.com","www.google-analytics.com",
               "www.googletagmanager.com","connect.facebook.net","platform.twitter.com"}
    scr_f = []
    for s in data["scripts"]:
        if not s.startswith("http"): continue
        netloc = urlparse(s).netloc
        if netloc==dom or netloc in TRUSTED: continue
        scr_f.append(F("Scripts","LOW",3,f"Unknown ext script: {netloc}",s[:80]))
        if len(scr_f)>=3: break   # max 3 → 9 pts

    # 5. IFRAMES — only unknown-domain iframes, capped
    iframe_f = [F("IFrame","LOW",4,f"IFrame from: {urlparse(s).netloc or s[:40]}","3rd-party content.")
                for s in data["iframes"]
                if urlparse(s).netloc!=dom][:2]   # max 8 pts

    # 6. DANGEROUS CODE PATTERNS — these push score into CRITICAL territory
    code_f = [F("Code",sev,sc,desc,det) for pat,sev,sc,desc,det in [
        (r"eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(",
         "CRITICAL",40,"eval() obfuscation detected","Arbitrary code exec risk."),
        (r"base64_decode\s*\(|base64\.b64decode",
         "HIGH",25,"Server-side base64 decode","Possible payload delivery."),
        (r"fromCharCode\s*\(\s*\d{2,3}\s*,",
         "HIGH",20,"fromCharCode string building","String obfuscation."),
        (r"cryptominer|coinhive|xmrig|minero|deepminer|jsecoin",
         "CRITICAL",50,"Crypto-miner script found","Browser CPU hijacking."),
        (r"(?:api_key|api_secret|passwd)\s*=\s*['\"][^'\"]{8,}['\"]",
         "CRITICAL",40,"Hardcoded credential exposed","Secret key in source."),
        (r"<!--.*?(private_key|secret_key|auth_token).*?-->",
         "HIGH",20,"Sensitive value in HTML comment",""),
    ] if re.search(pat,resp["text"],re.IGNORECASE|re.DOTALL)]

    # 7. REDIRECTS
    red_f = ([F("Redirect","LOW",5,"Cross-domain redirect",
               f"{dom} → {urlparse(resp['final_url']).netloc}")]
             if dom!=urlparse(resp["final_url"]).netloc else [])
    meta_f = ([F("Meta","LOW",4,"Meta refresh redirect",data["meta"].get("refresh",""))]
              if data["meta"].get("refresh","") else [])

    # 8. MALWARE / EXPLOIT INTEL — only fire on genuine malware signatures
    intel_f = []
    if data["malware_kw"]:
        intel_f.append(F("Intel","CRITICAL",35,
                         f"Malware keywords: {', '.join(data['malware_kw'][:4])}","Detected in source."))
    if data["exploit_kw"]:
        intel_f.append(F("Intel","HIGH",15,
                         f"Exploit keywords: {', '.join(data['exploit_kw'][:4])}","Attack surface."))
    # Only flag encoded blobs when properly padded base64 (=) found — rare on clean sites
    if data["encoded"]:
        intel_f.append(F("Intel","MEDIUM",6,
                         f"{len(data['encoded'])} encoded blob(s) detected","Obfuscation risk."))

    all_f = reduce(lambda a,b:a+b,
                   [ssl_f,hdr_f,form_f,scr_f,iframe_f,code_f,red_f,meta_f,intel_f])
    score = min(sum(f["score"] for f in all_f), 100)

    # Thresholds calibrated so:
    #   google/github  → 10-25 → SAFE or LOW
    #   testphp etc.   → 40-65 → MEDIUM
    #   eicar/malware  → 85+   → CRITICAL
    level = ("CRITICAL" if score>=80 else
             "HIGH"     if score>=60 else
             "MEDIUM"   if score>=35 else
             "LOW"      if score>=15 else "SAFE")
    return all_f, score, level

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY FUNCTION 4 — build_pdf                                            ║
# ║  PURPOSE : Generates a professional threat intelligence PDF report      ║
# ║  SECTIONS: Overview, score, findings, intel, + user-selected content   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def build_pdf(state, path):
    doc = SimpleDocTemplate(path, pagesize=letter,
                            leftMargin=.7*inch,rightMargin=.7*inch,
                            topMargin=.7*inch,bottomMargin=.7*inch)
    S  = getSampleStyleSheet()
    mk = lambda n,**k: ParagraphStyle(n,parent=S["Normal"],**k)
    h1 = mk("h1",fontSize=20,fontName="Helvetica-Bold",textColor=RC.HexColor("#00d4ff"),spaceAfter=4)
    h2 = mk("h2",fontSize=11,fontName="Helvetica-Bold",textColor=RC.HexColor("#7c3aed"),spaceBefore=10,spaceAfter=4)
    bd = mk("bd",fontSize=8,leading=12)
    dm = mk("dm",fontSize=7,leading=10,textColor=RC.HexColor("#555"))
    def T(rows,cols):
        t=Table(rows,colWidths=cols)
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),RC.HexColor("#1a2744")),
            ("TEXTCOLOR",(0,0),(-1,0),RC.HexColor("#00d4ff")),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),.4,RC.HexColor("#1a2744")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[RC.HexColor("#0c1220"),RC.HexColor("#080d1a")]),
            ("TEXTCOLOR",(0,1),(-1,-1),RC.HexColor("#c0cfe0")),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),7),
        ]))
        return t
    d=state["data"]; sel=state.get("selected_sections",{})
    story=[
        Paragraph("CYBER-PULSE PRO",h1),
        Paragraph(f"Threat Intelligence Report  |  {state['timestamp']}",dm),
        HRFlowable(width="100%",thickness=2,color=RC.HexColor("#00d4ff"),spaceAfter=8),
        Paragraph("Target Overview",h2),
        T([["Field","Value"],["URL",state["url"]],["IP",state["ip"]],
           ["HTTP",str(state["status"])],["Time",f"{state['elapsed']}s"],
           ["Title",d["title"][:80]],["Scripts",str(len(d["scripts"]))],
           ["Images",str(len(d["images"]))],["Forms",str(len(d["forms"]))],
           ["IPs Found",str(len(d["ips_found"]))],["Malware KW",str(len(d["malware_kw"]))]],
          [1.8*inch,5.5*inch]),
        Spacer(1,8),
        Paragraph("Threat Score",h2),
        T([["Score","Level","Summary"],
           [Paragraph(f"<b><font size='18'>{state['score']}/100</font></b>",bd),
            Paragraph(f"<b><font size='13'>{state['level']}</font></b>",bd),
            Paragraph({"CRITICAL":"Severe - immediate action required.","HIGH":"Significant weaknesses.",
                       "MEDIUM":"Moderate risk.","LOW":"Minor issues.","SAFE":"No major threats."
                       }.get(state["level"],""),bd)]],
          [1.3*inch,1.5*inch,4.5*inch]),
        Spacer(1,8),
        Paragraph("Threat Intelligence",h2),
        T([["Category","Findings"],
           ["IPs Detected",", ".join(d["ips_found"][:8]) or "None"],
           ["Malware Keywords",", ".join(d["malware_kw"]) or "None"],
           ["Exploit Keywords",", ".join(d["exploit_kw"]) or "None"],
           ["Encoded Blobs",f"{len(d['encoded'])} detected" if d["encoded"] else "None"],
           ["URLs in Source",str(len(d["urls_in_src"]))]],
          [1.8*inch,5.5*inch]),
        Spacer(1,8),Paragraph("Security Findings",h2),
    ]
    cats={}
    [cats.setdefault(f["cat"],[]).append(f) for f in state["findings"]]
    for cat,items in cats.items():
        story.append(Paragraph(f"> {cat}",mk("ch",fontSize=9,fontName="Helvetica-Bold",
                                              textColor=RC.HexColor("#00d4ff"),spaceBefore=5,spaceAfter=2)))
        rows=[["Severity","Description","Detail"]]
        for f in items:
            c=RC.HexColor(SEV.get(f["sev"],"#888"))
            rows.append([Paragraph(f"<b><font color='#{c.hexval()[2:]}'>{f['sev']}</font></b>",dm),
                         Paragraph(f["desc"],dm),Paragraph(f["detail"][:90],dm)])
        story+=[T(rows,[.9*inch,2.5*inch,4.1*inch]),Spacer(1,3)]
    for section,label in [("metadata","Page Metadata"),("text","Scraped Text"),
                           ("images","Images"),("links","Links & URLs")]:
        if not sel.get(section,True): continue
        story+=[Spacer(1,8),Paragraph(label,h2)]
        d2=state["data"]
        if section=="metadata":
            rows=[["Key","Value"]]+[[k,v[:70]] for k,v in list(d2["meta"].items())[:20]]
            if len(rows)>1: story.append(T(rows,[2.5*inch,4.8*inch]))
        elif section=="text":
            story.append(Paragraph(d2["text"][:1500].replace("<","&lt;"),dm))
        elif section=="images":
            rows=[["URL","Alt","Size"]]+[[img["src"][:55],img["alt"][:25],f"{img['w']}x{img['h']}"] for img in d2["images"][:20]]
            if len(rows)>1: story.append(T(rows,[4*inch,2*inch,1.3*inch]))
        elif section=="links":
            rows=[["URL"]]+[[l[:90]] for l in (d2["ext_links"]+d2["urls_in_src"])[:30]]
            if len(rows)>1: story.append(T(rows,[7.3*inch]))
    story+=[Spacer(1,12),
            HRFlowable(width="100%",thickness=1,color=RC.HexColor("#1a2744"),spaceAfter=4),
            Paragraph("Generated by Cyber-Pulse Pro. For authorized use only.",dm)]
    doc.build(story)

# ══════════════════════════════════════════════════════════════════════════════
#  GUI COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY CLASS 5 — MatrixCanvas                                            ║
# ║  PURPOSE : Renders the animated falling-character background effect     ║
# ║  HOW     : Draws katakana/binary chars column by column, scrolling down ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class MatrixCanvas(tk.Canvas):
    CHARS = "0101!@#$%^&*()[]{}<>?/|\\~`" 
    def __init__(self, master, **kw):
        kw.pop("bg", None)
        super().__init__(master, bg="#050810", highlightthickness=0, **kw)
        self.cols = []
        self.after(200, self._init)
        self.after(80, self._draw)

    def _init(self):
        w = self.winfo_width() or 1200
        self.cols = [{"x":i*18,"y":random.randint(-500,0),
                      "speed":random.uniform(1.5,4),"len":random.randint(8,25)}
                     for i in range(w//18+2)]

    def _draw(self):
        self.delete("m")
        h = self.winfo_height() or 800
        for col in self.cols:
            for j in range(col["len"]):
                y = col["y"] - j*14
                if 0 < y < h:
                    color = "#00ffcc" if j==0 else "#00d4ff" if j<3 else \
                            f"#00{min(60+int(140*(1-j/col['len'])),255):02x}50"
                    self.create_text(col["x"],y,
                        text=random.choice(self.CHARS) if j==0 else self.CHARS[j%len(self.CHARS)],
                        fill=color,font=("Courier",10),tags="m")
            col["y"] += col["speed"]
            if col["y"] > h+col["len"]*14:
                col["y"]=random.randint(-300,-50); col["speed"]=random.uniform(1.5,4)
        self.after(60, self._draw)

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY CLASS 6 — ScoreRing                                               ║
# ║  PURPOSE : Animated circular gauge showing the 0-100 threat score       ║
# ║  HOW     : Draws arc that sweeps proportionally; animates to target     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class ScoreRing(tk.Canvas):
    def __init__(self, master, **kw):
        kw.pop("bg", None)
        super().__init__(master, width=140, height=140, bg=C["panel"], highlightthickness=0, **kw)
        self._score=0; self._target=0; self._color=C["accent"]; self._redraw(0)

    def set_score(self, score, level):
        self._target=score; self._color=SEV.get(level,C["accent"]); self._anim()

    def _anim(self):
        if self._score<self._target:
            self._score=min(self._score+2,self._target); self._redraw(self._score); self.after(16,self._anim)
        else:
            self._redraw(self._score)

    def _redraw(self, score):
        self.delete("all"); cx=cy=70; r=52
        self.create_arc(cx-r,cy-r,cx+r,cy+r,start=90,extent=-360,outline=C["muted"],width=8,style="arc")
        self.create_arc(cx-r,cy-r,cx+r,cy+r,start=90,extent=-360*score/100,outline=self._color,width=8,style="arc")
        self.create_text(cx,cy-8,text=str(score),font=("Courier",22,"bold"),fill=self._color)
        self.create_text(cx,cy+14,text="/100",font=("Courier",10),fill=C["textdim"])

class PulseButton(ctk.CTkButton):
    def __init__(self,*a,**kw): super().__init__(*a,**kw); self._on=False
    def start_pulse(self):
        self._on=True; self._pulse()
    def stop_pulse(self):
        self._on=False
        try: self.configure(fg_color=C["accent"],text_color=C["bg"])
        except: pass
    def _pulse(self):
        if not self._on: return
        v=int(abs(math.sin(time.time()*3))*60)
        try: self.configure(fg_color=f"#00{min(0xd4+v,0xff):02x}{min(0xff,0xaa+v):02x}")
        except: pass
        self.after(40,self._pulse)

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  KEY CLASS 7 — CyberPulsePro (Main App)                                ║
# ║  PURPOSE : Root application window — wires all components together      ║
# ║  FLOW    : URL input > _scan() > _run_scan() thread > _render() results ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class CyberPulsePro(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CYBER-PULSE PRO  |  Web Threat Intelligence")
        self.geometry("1280x860"); self.minsize(1100,750)
        self.configure(fg_color=C["bg"])
        self.state_data=None; self._img_refs=[]; self._checks={}
        self._build()

    def _build(self):
        self._build_bg(); self._build_header(); self._build_urlbar(); self._build_content()

    def _build_bg(self):
        self.matrix=MatrixCanvas(self)
        self.matrix.place(x=0,y=0,relwidth=1,relheight=1)

    def _build_header(self):
        hdr=ctk.CTkFrame(self,fg_color=C["panel"],corner_radius=0,height=70)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        logo=ctk.CTkFrame(hdr,fg_color="transparent"); logo.pack(side="left",padx=24,pady=10)
        ctk.CTkLabel(logo,text="[*]",font=("Courier",22,"bold"),text_color=C["accent"]).pack(side="left",padx=(0,8))
        nf=ctk.CTkFrame(logo,fg_color="transparent"); nf.pack(side="left")
        ctk.CTkLabel(nf,text="CYBER-PULSE PRO",font=("Courier",18,"bold"),text_color=C["accent"]).pack(anchor="w")
        ctk.CTkLabel(nf,text="Web Threat Intelligence Platform",font=("Courier",9),text_color=C["dim"]).pack(anchor="w")
        right=ctk.CTkFrame(hdr,fg_color="transparent"); right.pack(side="right",padx=20)
        self.time_lbl=ctk.CTkLabel(right,text="",font=("Courier",10),text_color=C["dim"]); self.time_lbl.pack(anchor="e")
        self.export_btn=ctk.CTkButton(right,text="EXPORT PDF",width=140,height=32,
                                       fg_color="transparent",border_width=1,border_color=C["accent2"],
                                       text_color=C["accent2"],hover_color="#3d1f7a",
                                       font=("Courier",11,"bold"),command=self._export,state="disabled")
        self.export_btn.pack(anchor="e",pady=(4,0))
        self._tick()

    def _tick(self):
        self.time_lbl.configure(text=datetime.now().strftime("[ %Y-%m-%d  %H:%M:%S ]"))
        self.after(1000,self._tick)

    def _build_urlbar(self):
        bar=ctk.CTkFrame(self,fg_color=C["card"],corner_radius=12,height=62)
        bar.pack(fill="x",padx=16,pady=(10,0)); bar.pack_propagate(False)
        ctk.CTkLabel(bar,text="TARGET:",font=("Courier",10,"bold"),text_color=C["dim"]).pack(side="left",padx=(18,8))
        self.url_var=tk.StringVar()
        self.url_entry=ctk.CTkEntry(bar,textvariable=self.url_var,width=620,height=36,
                                     fg_color=C["bg"],border_color=C["border"],text_color=C["accent"],
                                     placeholder_text="https://target.com",placeholder_text_color=C["dim"],
                                     font=("Courier",13),corner_radius=8)
        self.url_entry.pack(side="left",pady=12)
        self.url_entry.bind("<Return>",lambda e:self._scan())
        self.scan_btn=PulseButton(bar,text="INITIATE SCAN",width=160,height=36,
                                   fg_color=C["accent"],hover_color="#00aacc",
                                   text_color=C["bg"],font=("Courier",12,"bold"),
                                   corner_radius=8,command=self._scan)
        self.scan_btn.pack(side="left",padx=12)
        self.status_var=tk.StringVar(value="READY")
        self.status_lbl=ctk.CTkLabel(bar,textvariable=self.status_var,font=("Courier",11,"bold"),text_color=C["dim"])
        self.status_lbl.pack(side="left",padx=8)

    def _build_content(self):
        main=ctk.CTkFrame(self,fg_color="transparent"); main.pack(fill="both",expand=True,padx=16,pady=10)

        # Left panel
        left=ctk.CTkFrame(main,fg_color=C["panel"],corner_radius=12,width=260)
        left.pack(side="left",fill="y",padx=(0,10)); left.pack_propagate(False)
        ctk.CTkLabel(left,text="THREAT SCORE",font=("Courier",10,"bold"),text_color=C["dim"]).pack(pady=(16,4))
        self.ring=ScoreRing(left); self.ring.pack(pady=4)
        self.level_lbl=ctk.CTkLabel(left,text="-- PENDING --",font=("Courier",13,"bold"),text_color=C["dim"])
        self.level_lbl.pack(pady=2)
        self.ip_lbl=ctk.CTkLabel(left,text="",font=("Courier",9),text_color=C["textdim"]); self.ip_lbl.pack()
        self.resp_lbl=ctk.CTkLabel(left,text="",font=("Courier",9),text_color=C["textdim"]); self.resp_lbl.pack()
        ctk.CTkFrame(left,fg_color=C["border"],height=1).pack(fill="x",padx=16,pady=12)

        # Module selector — metadata, text, images, links only
        ctk.CTkLabel(left,text="SELECT MODULES",font=("Courier",10,"bold"),text_color=C["dim"]).pack(pady=(0,8))
        for key,label in [("metadata","[M] Metadata"),("text","[T] Scraped Text"),
                          ("images","[I] Images"),("links","[L] Links & URLs")]:
            var=tk.BooleanVar(value=True); self._checks[key]=var
            ctk.CTkCheckBox(left,text=label,variable=var,font=("Courier",11),text_color=C["text"],
                            fg_color=C["accent"],hover_color=C["accent2"],checkmark_color=C["bg"],
                            corner_radius=4,border_color=C["border"]).pack(anchor="w",padx=20,pady=3)
        ctk.CTkFrame(left,fg_color=C["border"],height=1).pack(fill="x",padx=16,pady=12)

        # Quick stats
        ctk.CTkLabel(left,text="QUICK STATS",font=("Courier",10,"bold"),text_color=C["dim"]).pack(pady=(0,6))
        self._stats={}
        for key,icon in [("scripts","Scripts"),("images","Images"),("forms","Forms"),
                          ("ips","IPs Found"),("mal","Malware KW"),("enc","Encoded")]:
            row=ctk.CTkFrame(left,fg_color="transparent"); row.pack(fill="x",padx=12,pady=1)
            ctk.CTkLabel(row,text=icon,font=("Courier",10),text_color=C["textdim"],width=90,anchor="w").pack(side="left")
            lbl=ctk.CTkLabel(row,text="--",font=("Courier",10,"bold"),text_color=C["accent"]); lbl.pack(side="right",padx=8)
            self._stats[key]=lbl

        # Right tabs
        right=ctk.CTkFrame(main,fg_color="transparent"); right.pack(side="left",fill="both",expand=True)
        self.tabs=ctk.CTkTabview(right,fg_color=C["panel"],
                                  segmented_button_fg_color=C["card"],
                                  segmented_button_selected_color=C["accent2"],
                                  segmented_button_selected_hover_color="#6028c0",
                                  segmented_button_unselected_color=C["card"],
                                  segmented_button_unselected_hover_color=C["border"],
                                  corner_radius=12)
        self.tabs.pack(fill="both",expand=True)
        for t in ["INTEL","METADATA","TEXT","IMAGES","LINKS"]:
            self.tabs.add(t)
        self.intel_box = self._textbox(self.tabs.tab("INTEL"))
        self.meta_box  = self._textbox(self.tabs.tab("METADATA"))
        self.text_box  = self._textbox(self.tabs.tab("TEXT"))
        self.img_frame = ctk.CTkScrollableFrame(self.tabs.tab("IMAGES"),fg_color=C["bg"],corner_radius=8)
        self.img_frame.pack(fill="both",expand=True,padx=4,pady=4)
        self.link_box  = self._textbox(self.tabs.tab("LINKS"))

    def _textbox(self, parent):
        b=ctk.CTkTextbox(parent,fg_color=C["bg"],corner_radius=8,font=("Courier",11),
                          text_color=C["text"],wrap="word",scrollbar_button_color=C["border"])
        b.pack(fill="both",expand=True,padx=4,pady=4); return b

    # ── Scan ─────────────────────────────────────────────────────────────

    def _scan(self):
        url=self.url_var.get().strip()
        if not url: return
        self.scan_btn.configure(state="disabled"); self.scan_btn.start_pulse()
        self.export_btn.configure(state="disabled")
        self._clear(); self._status("INITIALIZING...",C["accent"])
        url=url if url.startswith(("http://","https://")) else "https://"+url
        threading.Thread(target=self._run_scan,args=(url,),daemon=True).start()

    def _clear(self):
        for b in [self.intel_box,self.meta_box,self.text_box,self.link_box]:
            b.configure(state="normal"); b.delete("1.0","end")
        for w in self.img_frame.winfo_children(): w.destroy()
        self._img_refs.clear()

    def _status(self,msg,color=None):
        self.after(0,lambda:self.status_var.set(msg))
        if color: self.after(0,lambda:self.status_lbl.configure(text_color=color))

    # ╔════════════════════════════════════════════════════════════════════╗
    # ║  KEY METHOD 8 — _run_scan                                        ║
    # ║  PURPOSE : Background thread running the full 3-stage pipeline    ║
    # ║  STAGE 1 : fetch_url  — download target                          ║
    # ║  STAGE 2 : parse_page — extract intelligence from HTML            ║
    # ║  STAGE 3 : run_checks — score threats, compute level              ║
    # ╚════════════════════════════════════════════════════════════════════╝
    def _run_scan(self, url):
        try:
            self._status("FETCHING TARGET...",C["accent"])
            resp=fetch_url(url)
            if not resp["ok"]: self._status(f"ERROR: {resp['error']}",C["red"]); self._done(); return
            self._status("PARSING HTML...",C["accent"])
            data=parse_page(resp["text"],url)
            self._status("RUNNING THREAT CHECKS...",C["orange"])
            findings,score,level=run_checks(url,resp,data)
            ip=resolve_ip(urlparse(url).hostname or "")
            self.state_data={"url":url,"ip":ip,"status":resp["status"],"elapsed":resp["elapsed"],
                             "findings":findings,"score":score,"level":level,"data":data,
                             "resp_headers":resp["headers"],
                             "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.after(0,self._render)
        except Exception as e:
            self._status(f"FAILED: {e}",C["red"]); self._done()

    def _render(self):
        s=self.state_data; d=s["data"]; lc=SEV.get(s["level"],C["accent"])
        self.ring.set_score(s["score"],s["level"])
        self.level_lbl.configure(text=f"[ {s['level']} ]",text_color=lc)
        self.ip_lbl.configure(text=f"IP: {s['ip']}")
        self.resp_lbl.configure(text=f"HTTP {s['status']}  |  {s['elapsed']}s")
        self._stats["scripts"].configure(text=str(len(d["scripts"])))
        self._stats["images"].configure(text=str(len(d["images"])))
        self._stats["forms"].configure(text=str(len(d["forms"])))
        self._stats["ips"].configure(text=str(len(d["ips_found"])))
        self._stats["mal"].configure(text=str(len(d["malware_kw"])),
                                     text_color=C["red"] if d["malware_kw"] else C["green"])
        self._stats["enc"].configure(text=str(len(d["encoded"])),
                                     text_color=C["orange"] if d["encoded"] else C["green"])
        self._write(self.intel_box, self._intel(s))
        if self._checks["metadata"].get(): self._write(self.meta_box, self._meta(s))
        if self._checks["text"].get():     self._write(self.text_box, self._txt(d))
        if self._checks["links"].get():    self._write(self.link_box, self._lnk(d))
        if self._checks["images"].get():
            threading.Thread(target=self._load_imgs,args=(d["images"],),daemon=True).start()
        self._status(f"DONE  |  {len(s['findings'])} findings  |  Score: {s['score']}/100",C["green"])
        self.export_btn.configure(state="normal"); self._done()

    def _write(self, box, text):
        box.configure(state="normal"); box.delete("1.0","end")
        box.insert("end",text); box.configure(state="disabled")

    # ── Content formatters ────────────────────────────────────────────────

    def _intel(self, s):
        d=s["data"]; div="="*58
        cats={}
        [cats.setdefault(f["cat"],[]).append(f) for f in s["findings"]]
        icon={"CRITICAL":"[!!!]","HIGH":"[!! ]","MEDIUM":"[!  ]","LOW":"[.  ]","INFO":"[ OK]"}
        findings_txt=[]
        for cat,items in cats.items():
            findings_txt.append(f"\n  +-- {cat.upper()} {'-'*(44-len(cat))}")
            for f in items:
                findings_txt.append(f"  |  {icon.get(f['sev'],'[?]')} [{f['sev']}] {f['desc']}")
                if f["detail"]: findings_txt.append(f"  |        >> {f['detail']}")
            findings_txt.append("  +" + "-"*50)
        blocks=[
            ("IP ADDRESSES DETECTED IN SOURCE",
             "\n".join(f"  >> {ip}" for ip in d["ips_found"][:20]) or "  [OK] None found"),
            ("MALWARE / SUSPICIOUS KEYWORDS",
             "\n".join(f"  !! {k}" for k in d["malware_kw"]) or "  [OK] None detected"),
            ("EXPLOIT / ATTACK KEYWORDS",
             "\n".join(f"  !! {k}" for k in d["exploit_kw"]) or "  [OK] None found"),
            ("ENCODED / OBFUSCATED CONTENT",
             "\n".join(f"  ~~ {e[:80]}" for e in d["encoded"][:5]) or "  [OK] None detected"),
            (f"URLS EXTRACTED ({len(d['urls_in_src'])} total)",
             "\n".join(f"  -> {u[:88]}" for u in d["urls_in_src"][:25])),
            ("SECURITY FINDINGS", "\n".join(findings_txt)),
        ]
        lines=["="*58,"  CYBER-PULSE PRO  --  THREAT INTELLIGENCE REPORT","="*58,
               f"  TARGET  : {s['url']}",f"  IP      : {s['ip']}",
               f"  SCANNED : {s['timestamp']}",f"  SCORE   : {s['score']}/100  [{s['level']}]"]
        for title,body in blocks:
            lines+=[f"\n{div}",f"  {title}",div,body]
        return "\n".join(lines)

    def _meta(self, s):
        d=s["data"]; div="="*58
        lines=["="*58,"  PAGE METADATA","="*58,
               f"  Title   : {d['title']}",f"  IP      : {s['ip']}",
               f"  Status  : {s['status']}",f"  Time    : {s['elapsed']}s",
               f"  Scripts : {len(d['scripts'])}   IFrames: {len(d['iframes'])}   Forms: {len(d['forms'])}",
               f"  Images  : {len(d['images'])}   Links: {len(d['links'])}   Ext: {len(d['ext_links'])}",
               f"  Comments: {d['comments']}",f"\n{div}  HTTP RESPONSE HEADERS",div]
        for k,v in s["resp_headers"].items(): lines.append(f"  {k}: {v}")
        lines+=[f"\n{div}  META TAGS",div]
        for k,v in d["meta"].items(): lines.append(f"  {k:<24}: {v[:70]}")
        lines+=[f"\n{div}  SCRIPTS",div]
        for sc in d["scripts"]: lines.append(f"  >> {sc}")
        lines+=[f"\n{div}  HEADINGS",div]
        for h in d["headings"]: lines.append(f"  -> {h}")
        return "\n".join(lines)

    def _txt(self, d):
        return ("="*58+"\n  SCRAPED PAGE TEXT\n"+"="*58+"\n\n"+d["text"])

    def _lnk(self, d):
        div="="*58
        lines=["="*58,"  LINKS & URLS EXTRACTED","="*58,
               f"\n{div}  ALL LINKS ({len(d['links'])} total)",div]
        for l in d["links"][:60]: lines.append(f"  -> {l}")
        lines+=[f"\n{div}  EXTERNAL LINKS ({len(d['ext_links'])} total)",div]
        for l in d["ext_links"][:30]: lines.append(f"  !! {l}")
        lines+=[f"\n{div}  URLS IN SOURCE ({len(d['urls_in_src'])} total)",div]
        for u in d["urls_in_src"]: lines.append(f"  >> {u[:88]}")
        return "\n".join(lines)

    def _load_imgs(self, images):
        for info in images[:24]:
            try:
                r=req.get(info["src"],timeout=5,verify=False)
                pil=Image.open(io.BytesIO(r.content)).convert("RGBA"); pil.thumbnail((160,160))
                ci=ctk.CTkImage(pil,size=pil.size)
                self.after(0,self._img_card,ci,info)
            except: pass

    def _img_card(self, ci, info):
        card=ctk.CTkFrame(self.img_frame,fg_color=C["card2"],corner_radius=10,
                           border_width=1,border_color=C["border"])
        card.pack(side="left",padx=8,pady=8,anchor="nw")
        ctk.CTkLabel(card,image=ci,text="").pack(padx=8,pady=(8,4))
        self._img_refs.append(ci)
        ctk.CTkLabel(card,text=(info["alt"] or "no alt")[:22],font=("Courier",9,"bold"),
                     text_color=C["accent"],wraplength=160).pack(padx=6)
        ctk.CTkLabel(card,text=f"{info['w']}x{info['h']}",font=("Courier",8),
                     text_color=C["dim"]).pack(padx=6,pady=(0,8))

    def _done(self):
        self.after(0,lambda:(self.scan_btn.stop_pulse(),self.scan_btn.configure(state="normal")))

    # ╔════════════════════════════════════════════════════════════════════╗
    # ║  KEY METHOD 9 — _export                                          ║
    # ║  PURPOSE : Opens save dialog and calls build_pdf with state data  ║
    # ║  GATING  : Only active after a successful scan completes          ║
    # ╚════════════════════════════════════════════════════════════════════╝
    def _export(self):
        if not self.state_data: return
        dom=urlparse(self.state_data["url"]).netloc.replace(".","_")
        path=filedialog.asksaveasfilename(
            defaultextension=".pdf",filetypes=[("PDF Report","*.pdf")],
            initialfile=f"cyberpulse_{dom}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            title="Save Threat Intelligence Report")
        if not path: return
        self.state_data["selected_sections"]={k:v.get() for k,v in self._checks.items()}
        try:
            build_pdf(self.state_data,path)
            messagebox.showinfo("Exported",f"PDF saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed",str(e))

def resolve_ip(host):
    try: return socket.gethostbyname(host)
    except: return "Unresolvable"

if __name__=="__main__":
    CyberPulsePro().mainloop()
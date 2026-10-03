import hashlib
import ipaddress
import json
import os
import re
import socket
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = APP_DIR / "config"
DATA_DIR = APP_DIR / "data"
REPORT_DIR = APP_DIR / "reports"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

for folder in (CONFIG_DIR, DATA_DIR, REPORT_DIR, APP_DIR / "assets", APP_DIR / "tools"):
    folder.mkdir(parents=True, exist_ok=True)


def load_settings():
    defaults = {
        "shodan_api_key": "",
        "spiderfoot_url": "http://127.0.0.1:5001",
        "hibp_api_key": "",
    }
    if SETTINGS_FILE.exists():
        try:
            defaults.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass
    return defaults


def save_settings(settings):
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def classify_target(value: str):
    v = value.strip()
    if not v:
        return "unknown"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
        return "email"
    digits = re.sub(r"\D", "", v)
    if len(digits) >= 8 and (v.startswith("+") or sum(c.isdigit() for c in v) >= 8):
        return "phone"
    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", v):
        return "domain"
    if re.fullmatch(r"@?[A-Za-z0-9._-]{3,40}", v) and " " not in v:
        return "username"
    return "name"


def http_json(url, headers=None, timeout=12):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "SPECTRA/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def shodan_lookup(ip, api_key):
    if not api_key:
        return {"status": "not_configured", "message": "Add a Shodan API key in Settings."}
    url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?key={urllib.parse.quote(api_key)}"
    try:
        data = http_json(url)
        return {
            "status": "ok",
            "ip": data.get("ip_str"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "last_update": data.get("last_update"),
        }
    except urllib.error.HTTPError as e:
        return {"status": "error", "message": f"Shodan HTTP {e.code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def pwned_password_check(password):
    if not password:
        return {"status": "empty"}
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "SPECTRA/0.1", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            text = r.read().decode("utf-8", errors="replace")
        count = 0
        for line in text.splitlines():
            candidate, _, n = line.partition(":")
            if candidate.strip().upper() == suffix:
                count = int(n.strip())
                break
        return {"status": "ok", "exposed": count > 0, "count": count}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def file_metadata(path):
    p = Path(path)
    raw = p.read_bytes()
    return {
        "filename": p.name,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
        "note": "Local file fingerprint only. No facial identification is performed.",
    }


def spiderfoot_status(base_url):
    url = (base_url or "").strip().rstrip("/")
    if not url:
        return {"status": "not_configured"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SPECTRA/0.1"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return {"status": "reachable", "http_status": r.status, "url": url}
    except Exception as e:
        return {"status": "unreachable", "url": url, "message": str(e)}


class SpectraApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SPECTRA — Digital Exposure & OSINT Auditor")
        self.geometry("1100x720")
        self.minsize(900, 620)
        self.settings = load_settings()
        self.findings = []
        self.selected_image = None
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except Exception:
            pass

        header = ttk.Frame(self, padding=14)
        header.pack(fill="x")
        ttk.Label(header, text="SPECTRA", font=("Segoe UI", 24, "bold")).pack(side="left")
        ttk.Label(header, text="  Digital Exposure & OSINT Auditor", font=("Segoe UI", 12)).pack(side="left", pady=(9, 0))
        ttk.Label(header, text="Powered by Dhruv Kaushik", font=("Segoe UI", 9)).pack(side="right", pady=(12, 0))

        search = ttk.LabelFrame(self, text="Universal Search", padding=12)
        search.pack(fill="x", padx=14, pady=(0, 10))

        self.target_var = tk.StringVar()
        self.type_var = tk.StringVar(value="Type: —")
        entry = ttk.Entry(search, textvariable=self.target_var, font=("Segoe UI", 13))
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        entry.bind("<KeyRelease>", lambda e: self._refresh_type())
        entry.bind("<Return>", lambda e: self.run_scan())
        ttk.Label(search, textvariable=self.type_var, width=18).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(search, text="SCAN", command=self.run_scan).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(search, text="Upload Image", command=self.pick_image).grid(row=0, column=3, padx=(0, 8))
        ttk.Button(search, text="Settings", command=self.open_settings).grid(row=0, column=4)
        search.columnconfigure(0, weight=1)

        tools = ttk.Frame(self, padding=(14, 0))
        tools.pack(fill="x")
        ttk.Button(tools, text="Check My Password", command=self.password_dialog).pack(side="left")
        ttk.Button(tools, text="Generate HTML Client Report", command=self.generate_report).pack(side="left", padx=8)
        ttk.Button(tools, text="Clear", command=self.clear_findings).pack(side="left")

        pane = ttk.Panedwindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=14, pady=12)

        left = ttk.LabelFrame(pane, text="Findings", padding=8)
        right = ttk.LabelFrame(pane, text="Details / Evidence", padding=8)
        pane.add(left, weight=1)
        pane.add(right, weight=2)

        self.tree = ttk.Treeview(left, columns=("type", "source"), show="headings")
        self.tree.heading("type", text="Finding")
        self.tree.heading("source", text="Source")
        self.tree.column("type", width=210)
        self.tree.column("source", width=150)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected)

        self.details = tk.Text(right, wrap="word", font=("Consolas", 10))
        self.details.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", side="bottom")

    def _refresh_type(self):
        t = classify_target(self.target_var.get())
        self.type_var.set(f"Type: {t.upper() if t != 'unknown' else '—'}")

    def add_finding(self, title, source, detail):
        item = {"title": title, "source": source, "detail": detail}
        self.findings.append(item)
        self.tree.insert("", "end", iid=str(len(self.findings)-1), values=(title, source))

    def show_selected(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.findings[int(sel[0])]
        self.details.delete("1.0", "end")
        self.details.insert("end", json.dumps(item["detail"], indent=2, ensure_ascii=False))

    def clear_findings(self):
        self.findings.clear()
        for x in self.tree.get_children():
            self.tree.delete(x)
        self.details.delete("1.0", "end")
        self.status_var.set("Cleared")

    def run_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showinfo("SPECTRA", "Enter a name, email, phone, username, domain or IP.")
            return
        typ = classify_target(target)
        self.status_var.set(f"Scanning {typ}: {target}")
        self.add_finding("Target classification", "SPECTRA", {"target": target, "type": typ})

        if typ == "ip":
            self.add_finding("Shodan host exposure", "Shodan", shodan_lookup(target, self.settings.get("shodan_api_key", "")))
        elif typ == "domain":
            try:
                ips = sorted({x[4][0] for x in socket.getaddrinfo(target, None)})
                self.add_finding("DNS resolution", "Local DNS", {"domain": target, "ips": ips})
            except Exception as e:
                self.add_finding("DNS resolution", "Local DNS", {"status": "error", "message": str(e)})
        elif typ in ("email", "username", "name", "phone"):
            self.add_finding(
                "Public-footprint workflow",
                "SPECTRA",
                {
                    "status": "foundation",
                    "message": "MVP classifies the target and provides connector slots. SpiderFoot automation is the next integration layer.",
                    "target": target,
                    "target_type": typ,
                },
            )

        self.add_finding("SpiderFoot connector", "SpiderFoot", spiderfoot_status(self.settings.get("spiderfoot_url", "")))
        self.status_var.set("Scan complete")

    def pick_image(self):
        path = filedialog.askopenfilename(
            title="Select authorized image",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.webp *.bmp"), ("All files", "*.*")],
        )
        if not path:
            return
        self.selected_image = path
        self.add_finding("Image fingerprint", "Local analysis", file_metadata(path))
        self.status_var.set(f"Image analyzed: {Path(path).name}")

    def password_dialog(self):
        win = tk.Toplevel(self)
        win.title("Check My Password")
        win.geometry("480x210")
        win.transient(self)
        ttk.Label(
            win,
            text="Enter a password you own/are authorized to test.\nSPECTRA sends only a SHA-1 prefix to the Pwned Passwords service.",
            padding=12,
        ).pack(fill="x")
        value = tk.StringVar()
        entry = ttk.Entry(win, textvariable=value, show="•", font=("Segoe UI", 12))
        entry.pack(fill="x", padx=14)
        result = tk.StringVar(value="")
        ttk.Label(win, textvariable=result, padding=12).pack(fill="x")

        def do_check():
            r = pwned_password_check(value.get())
            value.set("")
            if r.get("status") == "ok":
                if r.get("exposed"):
                    result.set(f"Known exposed password: YES — observed {r['count']:,} times.")
                else:
                    result.set("No match found in the Pwned Passwords corpus.")
                self.add_finding("Password exposure verification", "HIBP Pwned Passwords", r)
            else:
                result.set("Check failed: " + r.get("message", "Unknown error"))

        ttk.Button(win, text="Check", command=do_check).pack()
        entry.focus_set()

    def open_settings(self):
        win = tk.Toplevel(self)
        win.title("SPECTRA Settings")
        win.geometry("570x300")
        fields = [
            ("Shodan API key", "shodan_api_key", True),
            ("SpiderFoot URL", "spiderfoot_url", False),
            ("HIBP API key (reserved for breach-account connector)", "hibp_api_key", True),
        ]
        vars_ = {}
        for i, (label, key, secret) in enumerate(fields):
            ttk.Label(win, text=label).grid(row=i, column=0, sticky="w", padx=12, pady=10)
            var = tk.StringVar(value=self.settings.get(key, ""))
            vars_[key] = var
            ttk.Entry(win, textvariable=var, show="•" if secret else "").grid(row=i, column=1, sticky="ew", padx=12)
        win.columnconfigure(1, weight=1)
        ttk.Label(
            win,
            text="Keys are stored locally in config/settings.json. That file is excluded from Git.",
            padding=12,
        ).grid(row=len(fields), column=0, columnspan=2, sticky="w")

        def save():
            for k, v in vars_.items():
                self.settings[k] = v.get().strip()
            save_settings(self.settings)
            messagebox.showinfo("SPECTRA", "Settings saved locally.")
            win.destroy()

        ttk.Button(win, text="Save", command=save).grid(row=len(fields)+1, column=1, sticky="e", padx=12, pady=10)

    def generate_report(self):
        if not self.findings:
            messagebox.showinfo("SPECTRA", "Run a scan first.")
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = REPORT_DIR / f"SPECTRA-report-{ts}.html"
        rows = []
        for f in self.findings:
            rows.append(
                "<section><h2>{}</h2><p><b>Source:</b> {}</p><pre>{}</pre></section>".format(
                    self._esc(f["title"]),
                    self._esc(f["source"]),
                    self._esc(json.dumps(f["detail"], indent=2, ensure_ascii=False)),
                )
            )
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>SPECTRA Client Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;max-width:980px;margin:40px auto;padding:0 20px;color:#171717}}
h1{{margin-bottom:0}} .sub{{color:#555;margin-top:4px}} section{{border:1px solid #ddd;border-radius:10px;padding:16px;margin:14px 0}}
pre{{white-space:pre-wrap;background:#f6f6f6;padding:12px;border-radius:8px}}
.notice{{background:#fff8dc;border:1px solid #ead58a;padding:12px;border-radius:8px}}
</style></head><body>
<h1>SPECTRA</h1><p class="sub">Digital Exposure & OSINT Auditor — Powered by Dhruv Kaushik</p>
<p>Generated: {datetime.now().isoformat(timespec="seconds")}</p>
<div class="notice">Use this report only for your own data/systems or where you have explicit authorization. Findings may include false positives and should be independently verified.</div>
{''.join(rows)}
</body></html>"""
        path.write_text(html, encoding="utf-8")
        self.status_var.set(f"Report saved: {path.name}")
        if messagebox.askyesno("SPECTRA", f"Report saved to:\n{path}\n\nOpen it now?"):
            webbrowser.open(path.as_uri())

    @staticmethod
    def _esc(s):
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )


def main():
    app = SpectraApp()
    app.mainloop()


if __name__ == "__main__":
    main()

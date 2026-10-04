"""SPECTRA desktop investigation workspace."""
import json
import math
import queue
import threading
import time
import uuid
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .core import APP_DIR, DEFAULTS, TYPES, CONFIDENCE, CaseStore, atomic_json, target, finding, merge_finding, now, report_html, risk
from .providers import CATALOG, Engine, Scanner, pwned_password_check
BG, PANEL, TEXT, MUTED, ACCENT = '#0b1220', '#121e31', '#e4ecf7', '#95a9c2', '#43d9c0'


class SpectraApp(tk.Tk):
    def __init__(self, start_engine=True, root=APP_DIR):
        super().__init__()
        self.title('SPECTRA · Investigation Workspace (0.3.1)')
        self.geometry('1380x850')
        self.minsize(1060, 700)
        self.configure(bg=BG)
        self.store = CaseStore(root)
        try:
            self.settings = self.store.settings()
        except (ValueError, OSError):
            self.settings = dict(DEFAULTS)
            messagebox.showwarning('Settings', 'Cannot read settings. Defaults loaded; original file preserved.')
        self.case = None
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.worker = None
        self.engine = Engine(root)
        self.active_scan = None
        self.started_at = None
        self.closing = False
        self.current_page = 'Dashboard'
        self.connector_states = {}
        self._theme()
        self._build_ui()
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self.after(100, self.poll)
        self.show_page('Dashboard')
        if start_engine and self.settings.get('spiderfoot_enabled'): self.check_engine()

    def _theme(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        s.configure('.', background=BG, foreground=TEXT, font=('Segoe UI', 10))
        s.configure('TFrame', background=BG)
        s.configure('TLabel', background=BG, foreground=TEXT)
        s.configure('Muted.TLabel', foreground=MUTED)
        s.configure('Title.TLabel', font=('Segoe UI', 23, 'bold'))
        s.configure('TButton', background='#22344d', foreground=TEXT, padding=(12, 9), borderwidth=0)
        s.map('TButton', background=[('active', '#304c6b'), ('disabled', '#162238')], foreground=[('disabled', '#61738b')])
        s.configure('Accent.TButton', background=ACCENT, foreground=BG)
        s.map('Accent.TButton', background=[('active', '#78ecd9')])
        s.configure('TEntry', fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT, padding=8)
        s.configure('TCombobox', fieldbackground=PANEL, background=PANEL, foreground=TEXT, padding=7)
        s.map('TCombobox', fieldbackground=[('readonly', PANEL)], foreground=[('readonly', TEXT)])
        s.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=34, borderwidth=0)
        s.configure('Treeview.Heading', background='#20324b', foreground=MUTED, padding=10, font=('Segoe UI', 10, 'bold'))
        s.map('Treeview', background=[('selected', '#28526b')])
        s.configure('TCheckbutton', background=BG, foreground=TEXT)
        s.map('TCheckbutton', background=[('active', BG)])
        s.configure('Horizontal.TProgressbar', troughcolor=PANEL, background=ACCENT, borderwidth=0)
        self.option_add('*TCombobox*Listbox.background', PANEL)
        self.option_add('*TCombobox*Listbox.foreground', TEXT)

    def text_widget(self, parent, **kwargs):
        return tk.Text(parent, bg=PANEL, fg=TEXT, insertbackground=TEXT, selectbackground='#28526b', relief='flat', padx=14, pady=12, wrap='word', font=('Segoe UI', 10), **kwargs)

    def button(self, parent, label, command, accent=False):
        b = ttk.Button(parent, text=label, command=command, style='Accent.TButton' if accent else 'TButton')
        b.pack(side='left', padx=(0, 8), pady=5)
        return b

    def table(self, parent, columns):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        table = ttk.Treeview(frame, columns=[c[0] for c in columns], show='headings', selectmode='browse')
        for key, title, width in columns:
            table.heading(key, text=title)
            table.column(key, width=width, minwidth=60)
        bar = ttk.Scrollbar(frame, orient='vertical', command=table.yview)
        table.configure(yscrollcommand=bar.set)
        bar.pack(side='right', fill='y')
        table.pack(fill='both', expand=True)
        return table

    def _build_ui(self):
        sidebar = tk.Frame(self, bg='#0e192b', width=210)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text='SPECTRA', font=('Segoe UI', 24, 'bold'), fg=ACCENT, bg='#0e192b').pack(anchor='w', padx=22, pady=(30, 2))
        tk.Label(sidebar, text='EXPOSURE INTELLIGENCE', font=('Segoe UI', 8), fg=MUTED, bg='#0e192b').pack(anchor='w', padx=24, pady=(0, 30))
        self.nav = {}
        for label in ('Dashboard', 'Investigation', 'Cases', 'Graph', 'Reports', 'Connectors', 'Settings', 'Logs'):
            b = tk.Button(sidebar, text=label, anchor='w', padx=22, pady=12, relief='flat', bd=0, font=('Segoe UI', 11), fg=TEXT, bg='#0e192b', activebackground='#21364d', activeforeground=ACCENT, command=lambda n=label: self.show_page(n))
            b.pack(fill='x', padx=10, pady=2)
            self.nav[label] = b
        tk.Label(sidebar, text='Powered by\nDhruv Kaushik', justify='left', font=('Segoe UI', 9), fg=MUTED, bg='#0e192b').pack(side='bottom', anchor='w', padx=24, pady=24)
        content = ttk.Frame(self, padding=(24, 20))
        content.pack(side='left', fill='both', expand=True)
        header = ttk.Frame(content)
        header.pack(fill='x', pady=(0, 18))
        self.page_title = tk.StringVar(value='Dashboard')
        ttk.Label(header, textvariable=self.page_title, style='Title.TLabel').pack(side='left')
        self.case_label = tk.StringVar(value='No case open')
        ttk.Label(header, textvariable=self.case_label, style='Muted.TLabel').pack(side='right')
        host = ttk.Frame(content)
        host.pack(fill='both', expand=True)
        self.pages = {name: ttk.Frame(host) for name in self.nav}
        for name in self.nav:
            if name != 'Logs': getattr(self, '_'+name.lower())(self.pages[name])
        self.logs = self.text_widget(self.pages['Logs'])
        self.logs.pack(fill='both', expand=True)
        self.logs.configure(state='disabled')
        self.status = tk.StringVar(value='Ready · Create or open a case to begin')
        ttk.Label(content, textvariable=self.status, style='Muted.TLabel').pack(fill='x', pady=(16, 0))

    def _dashboard(self, page):
        hero = tk.Frame(page, bg=PANEL, padx=26, pady=26)
        hero.pack(fill='x')
        tk.Label(hero, text='Understand your digital exposure.', bg=PANEL, fg=TEXT, font=('Segoe UI', 22, 'bold')).pack(anchor='w')
        tk.Label(hero, text='Build a case. Trace the evidence. Prioritize what matters.', bg=PANEL, fg=MUTED, font=('Segoe UI', 11)).pack(anchor='w', pady=(10, 20))
        actions = tk.Frame(hero, bg=PANEL)
        actions.pack(anchor='w')
        self.button(actions, '+ New investigation', self.new_case, True)
        self.button(actions, 'Open case', lambda: self.show_page('Cases'))
        cards = ttk.Frame(page)
        cards.pack(fill='x', pady=22)
        self.metrics = {}
        for key, title in [('targets', 'TARGETS'), ('findings', 'FINDINGS'), ('high', 'HIGH PRIORITY'), ('score', 'OBSERVED EXPOSURE')]:
            card = tk.Frame(cards, bg=PANEL, padx=20, pady=18)
            card.pack(side='left', fill='both', expand=True, padx=(0, 10))
            value = tk.StringVar(value='0')
            self.metrics[key] = value
            tk.Label(card, text=title, font=('Segoe UI', 8, 'bold'), bg=PANEL, fg=MUTED).pack(anchor='w')
            tk.Label(card, textvariable=value, font=('Segoe UI', 28, 'bold'), bg=PANEL, fg=ACCENT).pack(anchor='w', pady=(8, 0))
        ttk.Label(page, text='Case overview', font=('Segoe UI', 14, 'bold')).pack(anchor='w', pady=(0, 10))
        self.overview = self.text_widget(page, height=9)
        self.overview.pack(fill='both', expand=True)
        self.overview.insert('end', 'Start with a named case and an authorization note. Add one or more targets, choose your sources, and run an investigation.\n\nEvidence stays locally beside the application. Provider coverage and failures are shown explicitly. A zero exposure indicator does not establish safety.\n\nLocal image analysis and password checking are available from Investigation.')
        self.overview.configure(state='disabled')

    def _investigation(self, page):
        actions = ttk.Frame(page)
        actions.pack(fill='x')
        for label, fn in [('New case', self.new_case), ('Save case', self.save_case), ('Add image', self.pick_image), ('Check password', self.password_dialog)]: self.button(actions, label, fn)
        inputs = ttk.Frame(page)
        inputs.pack(fill='x', pady=(10, 3))
        self.target_value = tk.StringVar()
        ttk.Entry(inputs, textvariable=self.target_value).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.target_type = tk.StringVar(value='Auto')
        ttk.Combobox(inputs, values=TYPES, textvariable=self.target_type, width=12, state='readonly').pack(side='left', padx=(0, 8))
        self.button(inputs, 'Add target', self.add_target, True)
        self.target_summary = tk.StringVar(value='No targets added')
        ttk.Label(page, textvariable=self.target_summary, style='Muted.TLabel', wraplength=950).pack(anchor='w', pady=(0, 5))
        options = ttk.Frame(page)
        options.pack(fill='x')
        self.scan_button = self.button(options, 'Run investigation', self.run_scan, True)
        self.stop_button = self.button(options, 'Stop', self.stop_scan)
        self.stop_button.configure(state='disabled')
        self.button(options, 'Manage targets', self.manage_targets)
        self.pivot_value = tk.BooleanVar(value=self.settings.get('auto_pivot', False))
        ttk.Checkbutton(options, text='Auto pivot to DNS-derived IPs', variable=self.pivot_value).pack(side='left', padx=8)
        self.progress = ttk.Progressbar(page, mode='indeterminate')
        self.progress.pack(fill='x', pady=(8, 12))
        self.scan_notice = tk.StringVar(value='')
        ttk.Label(page, textvariable=self.scan_notice, style='Muted.TLabel', wraplength=950).pack(fill='x', pady=(0, 8))
        filters = ttk.Frame(page)
        filters.pack(fill='x', pady=(0, 8))
        ttk.Label(filters, text='Evidence').pack(side='left')
        self.search_value = tk.StringVar()
        ttk.Entry(filters, textvariable=self.search_value, width=26).pack(side='left', padx=10)
        self.search_value.trace_add('write', lambda *_: self.refresh_findings())
        self.confidence_value = tk.StringVar(value='ALL')
        cb = ttk.Combobox(filters, values=['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CONFIRMED'], textvariable=self.confidence_value, state='readonly', width=13)
        cb.pack(side='left')
        cb.bind('<<ComboboxSelected>>', lambda _: self.refresh_findings())
        self.button(filters, 'View raw evidence', self.raw_evidence)
        panes = ttk.Panedwindow(page, orient='vertical')
        panes.pack(fill='both', expand=True)
        top, bottom = ttk.Frame(panes), ttk.Frame(panes)
        panes.add(top, weight=3)
        panes.add(bottom, weight=2)
        self.findings_tree = self.table(top, [('severity', 'PRIORITY', 85), ('title', 'FINDING', 300), ('source', 'SOURCE', 100), ('confidence', 'CONFIDENCE', 110)])
        self.findings_tree.bind('<<TreeviewSelect>>', self.show_finding)
        self.detail = self.text_widget(bottom, height=7)
        self.detail.pack(fill='both', expand=True, pady=(8, 0))
        self.detail.configure(state='disabled')

    def _cases(self, page):
        row = ttk.Frame(page)
        row.pack(fill='x', pady=(0, 12))
        for label, fn in [('+ New case', self.new_case), ('Open selected', self.open_selected_case), ('Import JSON', self.import_case), ('Export current', self.export_case), ('Archive / restore', self.archive_case)]: self.button(row, label, fn)
        self.cases_tree = self.table(page, [('name', 'CASE', 270), ('client', 'CLIENT', 170), ('findings', 'FINDINGS', 90), ('state', 'STATE', 100), ('updated', 'UPDATED (UTC)', 200)])
        self.cases_tree.bind('<Double-1>', lambda _: self.open_selected_case())

    def _graph(self, page):
        row = ttk.Frame(page)
        row.pack(fill='x')
        self.button(row, 'Reset', self.draw_graph)
        self.button(row, '+ Zoom', lambda: self.zoom_graph(1.2))
        self.button(row, '− Zoom', lambda: self.zoom_graph(1/1.2))
        self.button(row, 'Add selected node', self.add_graph_target)
        self.graph_high = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text='Hide low-confidence relationships', variable=self.graph_high, command=self.draw_graph).pack(side='left', padx=8)
        ttk.Label(page, text='Drag to pan · Click a node for evidence · Wheel to zoom', style='Muted.TLabel').pack(anchor='w', pady=8)
        self.canvas = tk.Canvas(page, bg=PANEL, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        self.canvas.bind('<ButtonPress-1>', lambda e: self.canvas.scan_mark(e.x, e.y))
        self.canvas.bind('<B1-Motion>', lambda e: self.canvas.scan_dragto(e.x, e.y, gain=1))
        self.canvas.bind('<MouseWheel>', lambda e: self.zoom_graph(1.1 if e.delta > 0 else 1/1.1))
        self.graph_detail = tk.StringVar(value='No node selected')
        ttk.Label(page, textvariable=self.graph_detail, wraplength=950, style='Muted.TLabel').pack(fill='x', pady=10)

    def _reports(self, page):
        ttk.Label(page, text='Client reports with evidence, coverage, relationships and remediation.', style='Muted.TLabel').pack(anchor='w', pady=(0, 12))
        row = ttk.Frame(page)
        row.pack(fill='x', pady=(0, 14))
        self.button(row, 'Generate HTML report', self.generate_report, True)
        self.button(row, 'Open selected report', self.open_report)
        ttk.Label(page, text='For PDF: open the report and use Print → Save as PDF.', style='Muted.TLabel').pack(anchor='w', pady=(0, 14))
        self.reports_tree = self.table(page, [('name', 'REPORT', 500), ('created', 'CREATED (UTC)', 220)])

    def _connectors(self, page):
        ttk.Label(page, text='Public sources, local analysis, and optional API enrichment.', style='Muted.TLabel').pack(anchor='w', pady=(0, 12))
        row = ttk.Frame(page)
        row.pack(fill='x')
        self.button(row, 'Configure sources', lambda: self.show_page('Settings'), True)
        self.button(row, 'Check SpiderFoot', self.check_engine)
        self.button(row, 'Restart owned engine', self.restart_engine)
        self.connectors_tree = self.table(page, [('name', 'CONNECTOR', 110), ('access', 'ACCESS', 120), ('state', 'STATE', 125), ('supports', 'TARGETS', 160), ('description', 'CAPABILITY', 300)])

    def _settings(self, page):
        self.setting_vars = {}
        for label, key, secret in [('Shodan API key', 'shodan_api_key', True), ('HIBP API key', 'hibp_api_key', True), ('SpiderFoot URL', 'spiderfoot_url', False)]:
            row = ttk.Frame(page)
            row.pack(fill='x', pady=6)
            ttk.Label(row, text=label, width=22).pack(side='left')
            v = tk.StringVar(value=self.settings.get(key, ''))
            self.setting_vars[key] = v
            ttk.Entry(row, textvariable=v, show='•' if secret else '').pack(side='left', fill='x', expand=True)
        ttk.Label(page, text='Keys stay in local config/settings.json; excluded from case exports, reports and Git.', style='Muted.TLabel', wraplength=900).pack(anchor='w', pady=12)
        for label, key in [('Enable SpiderFoot passive engine', 'spiderfoot_enabled'), ('Developer mode: diagnostic controls', 'developer_mode')]:
            v = tk.BooleanVar(value=self.settings.get(key, False))
            self.setting_vars[key] = v
            ttk.Checkbutton(page, text=label, variable=v, command=self.toggle_developer).pack(anchor='w', pady=5)
        ttk.Label(page, text='Enabled sources', font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(14, 6))
        source_row = ttk.Frame(page)
        source_row.pack(fill='x')
        self.source_vars = {}
        for name, *_ in CATALOG:
            if name == 'SpiderFoot': continue
            v = tk.BooleanVar(value=name in self.settings.get('connectors', []))
            self.source_vars[name] = v
            ttk.Checkbutton(source_row, text=name, variable=v).pack(side='left', padx=(0, 12))
        self.dev_frame = ttk.Frame(page)
        for label, key in [('Pivot depth', 'pivot_depth'), ('Request timeout (seconds)', 'timeout'), ('Retries after transient errors', 'retries')]:
            row = ttk.Frame(self.dev_frame)
            row.pack(fill='x', pady=6)
            ttk.Label(row, text=label, width=30).pack(side='left')
            v = tk.StringVar(value=str(self.settings.get(key, 1)))
            self.setting_vars[key] = v
            ttk.Entry(row, textvariable=v, width=14).pack(side='left')
        ttk.Label(self.dev_frame, text='No case or finding count caps. Cancellation waits for the current request timeout.\nPivots follow DNS-derived IPs only. Sources retain their own rate limits.', style='Muted.TLabel', wraplength=900).pack(anchor='w', pady=12)
        self.toggle_developer()
        row = ttk.Frame(page)
        row.pack(fill='x', pady=15)
        self.button(row, 'Save settings', self.save_settings, True)

    def toggle_developer(self):
        if not hasattr(self, 'dev_frame'): return
        if self.setting_vars['developer_mode'].get(): self.dev_frame.pack(fill='x', pady=12)
        else: self.dev_frame.pack_forget()

    def show_page(self, name):
        for frame in self.pages.values(): frame.pack_forget()
        self.pages[name].pack(fill='both', expand=True)
        self.current_page = name
        self.page_title.set(name)
        for n, b in self.nav.items(): b.configure(bg='#21364d' if n == name else '#0e192b', fg=ACCENT if n == name else TEXT)
        if name == 'Cases': self.refresh_cases()
        if name == 'Connectors': self.refresh_connectors()
        if name == 'Reports': self.refresh_reports()
        if name == 'Graph': self.after(20, self.draw_graph)

    def busy(self):
        return self.active_scan is not None

    def require_case(self):
        if not self.case: self.new_case()
        return self.case is not None

    def new_case(self):
        if self.busy():
            messagebox.showinfo('Investigation running', 'Stop the current investigation before changing cases.')
            return
        win = tk.Toplevel(self)
        win.title('New investigation')
        win.configure(bg=BG)
        win.geometry('580x400')
        win.transient(self)
        values = []
        for label in ('Case name', 'Client / owner', 'Authorization / assessment scope (optional note)'):
            ttk.Label(win, text=label).pack(anchor='w', padx=24, pady=(15, 5))
            v = tk.StringVar()
            ttk.Entry(win, textvariable=v).pack(fill='x', padx=24)
            values.append(v)
        ttk.Label(win, text='Describe the systems or data you own or have permission to assess.', style='Muted.TLabel', wraplength=520).pack(anchor='w', padx=24, pady=12)
        def create():
            try:
                self.case = self.store.create(*(v.get() for v in values))
                self.refresh()
                win.destroy()
                self.show_page('Investigation')
            except (ValueError, OSError) as exc: messagebox.showerror('Cannot create case', str(exc), parent=win)
        ttk.Button(win, text='Create case', command=create, style='Accent.TButton').pack(anchor='e', padx=24, pady=12)
        win.grab_set()
        self.wait_window(win)

    def save_case(self, notify=True):
        if not self.case: return
        try:
            self.store.save(self.case)
            if notify: self.status.set('Case saved locally')
        except OSError: messagebox.showerror('Save failed', 'Could not write the case. Export a copy to a writable folder.')

    def add_target(self):
        if self.busy() or not self.require_case(): return
        try:
            t = target(self.target_value.get(), self.target_type.get())
            if t not in self.case['targets']: self.case['targets'].append(t)
            self.save_case()
            self.target_value.set('')
            self.refresh()
        except ValueError as exc: messagebox.showerror('Invalid target', str(exc))

    def pick_image(self):
        if self.busy() or not self.require_case(): return
        path = filedialog.askopenfilename(title='Select an authorized image', filetypes=[('Images', '*.png *.jpg *.jpeg *.webp *.bmp *.tif *.tiff')])
        if path:
            t = target(path, 'Image')
            if t not in self.case['targets']: self.case['targets'].append(t)
            self.save_case()
            self.refresh()
            self.show_page('Investigation')

    def manage_targets(self):
        if self.busy() or not self.require_case(): return
        win = tk.Toplevel(self)
        win.title('Case targets')
        win.geometry('650x380')
        win.configure(bg=BG)
        box = tk.Listbox(win, bg=PANEL, fg=TEXT, selectbackground='#28526b', relief='flat', font=('Segoe UI', 11))
        box.pack(fill='both', expand=True, padx=15, pady=15)
        for t in self.case['targets']: box.insert('end', t['type'] + ' · ' + t['value'])
        def remove():
            if box.curselection():
                i = box.curselection()[0]
                self.case['targets'].pop(i)
                box.delete(i)
                self.save_case()
                self.refresh()
        ttk.Button(win, text='Remove selected target (keeps prior evidence)', command=remove).pack(pady=12)
        win.transient(self)
        win.grab_set()

    def run_scan(self):
        if self.busy() or not self.require_case(): return
        if self.target_value.get().strip():
            self.add_target()
            if self.target_value.get().strip(): return
        if not self.case['targets']:
            messagebox.showinfo('Add a target', 'Add at least one target or image before running.')
            return
        if self.case.get('archived'):
            messagebox.showinfo('Archived case', 'Restore the case before scanning.')
            return
        self.cancel.clear()
        self.scan_notice.set('Starting investigation…')
        self.started_at = time.monotonic()
        self.active_scan = {'id': str(uuid.uuid4()), 'started': now(), 'status': 'RUNNING', 'warnings': [], 'targets': list(self.case['targets']), 'engine_scans': []}
        self.case['scans'].append(self.active_scan)
        settings = dict(self.settings)
        settings['auto_pivot'] = self.pivot_value.get()
        self.active_scan['providers'] = list(settings['connectors']) + (['SpiderFoot'] if settings.get('spiderfoot_enabled') else [])
        self.active_scan['auto_pivot'] = settings['auto_pivot']
        self.active_scan['pivot_depth'] = settings['pivot_depth']
        self.save_case()
        scanner = Scanner(settings, lambda event, value: self.events.put((event, value)), self.cancel, self.engine)
        self.worker = threading.Thread(target=scanner.run, args=(list(self.case['targets']),), daemon=True)
        self.scan_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress.start(12)
        self.worker.start()
        self.log('Investigation started.')

    def stop_scan(self):
        self.cancel.set()
        self.status.set('Stopping · waiting for the current provider request to finish')
        self.stop_button.configure(state='disabled')

    def poll(self):
        changed = False
        try:
            while True:
                event, value = self.events.get_nowait()
                if event == 'finding':
                    if self.case: merge_finding(self.case, value)
                    changed = True
                elif event == 'provider':
                    self.current_provider = value
                    self.connector_states[value.split(' · ')[0]] = 'RUNNING'
                elif event == 'provider_done': self.connector_states[value] = 'READY'
                elif event == 'warning':
                    self.log(value)
                    if self.active_scan: self.active_scan['warnings'].append(value)
                    self.scan_notice.set(value)
                    self.connector_states[value.split(':')[0]] = 'RATE LIMITED' if 'RATE LIMITED' in value else ('NOT CONFIGURED' if 'NOT CONFIGURED' in value else 'FAILED')
                elif event == 'engine_scan' and self.active_scan: self.active_scan['engine_scans'].append(value)
                elif event == 'engine_status':
                    self.connector_states['SpiderFoot'] = value
                    self.log('SpiderFoot: ' + value)
                    self.refresh_connectors()
                elif event == 'done':
                    if self.active_scan:
                        self.active_scan.update(value)
                        self.active_scan['finished'] = now()
                    self.progress.stop()
                    self.scan_button.configure(state='normal')
                    self.stop_button.configure(state='disabled')
                    self.started_at = None
                    self.active_scan = None
                    self.save_case()
                    self.status.set(value['status'])
                    self.scan_notice.set('\n'.join(dict.fromkeys(value.get('warnings', []))) or value['status'])
                    self.log(value['status'])
                    changed = True
                elif event == 'password':
                    callback, result = value
                    callback(result)
        except queue.Empty: pass
        if changed:
            self.refresh()
            self.save_case(notify=False)
        if self.started_at:
            elapsed = int(time.monotonic() - self.started_at)
            self.status.set(f"{getattr(self, 'current_provider', 'Preparing')} · {elapsed}s · {len(self.case['findings'])} findings · Stop available")
        if self.closing and not self.busy():
            self.save_case()
            self.engine.close()
            self.destroy()
            return
        self.after(100, self.poll)

    def log(self, text):
        self.logs.configure(state='normal')
        self.logs.insert('end', now() + '  ' + text + '\n')
        self.logs.see('end')
        self.logs.configure(state='disabled')

    def refresh(self):
        if not self.case: return
        self.case_label.set(self.case['name'] + '  ·  ' + self.case['id'][:8])
        score, counts = risk(self.case)
        for key, value in [('targets', len(self.case['targets'])), ('findings', len(self.case['findings'])), ('high', counts['HIGH']), ('score', str(score) + '/100')]: self.metrics[key].set(str(value))
        self.target_summary.set('Targets: ' + (' · '.join(t['value'] for t in self.case['targets']) or 'none'))
        if not self.busy() and self.case['scans']:
            latest = self.case['scans'][-1]
            self.scan_notice.set('\n'.join(dict.fromkeys(latest.get('warnings', []))) or latest['status'])
        self.overview.configure(state='normal')
        self.overview.delete('1.0', 'end')
        self.overview.insert('end', f"{self.case['name']}\nClient: {self.case['client'] or 'Not specified'}\nScope: {self.case['authorization']}\n\n{len(self.case['scans'])} scan runs · {len(self.case['findings'])} deduplicated findings\n\nExposure indicator: {score}/100. Heuristic: 25 per high, 10 per medium, 3 per low finding, capped at 100. A zero score does not establish safety.\n\n" + '\n'.join(s['started'] + ' · ' + s['status'] for s in self.case['scans'][-6:]))
        self.overview.configure(state='disabled')
        self.refresh_findings()
        if self.current_page == 'Graph': self.draw_graph()

    def refresh_findings(self):
        if not hasattr(self, 'findings_tree'): return
        selected = self.findings_tree.selection()
        self.findings_tree.delete(*self.findings_tree.get_children())
        if not self.case: return
        query, level = self.search_value.get().lower(), self.confidence_value.get()
        for f in self.case['findings']:
            if query and query not in (f['title'] + ' ' + f['summary'] + ' ' + f['source']).lower(): continue
            if level != 'ALL' and CONFIDENCE[f['confidence']] < CONFIDENCE[level]: continue
            self.findings_tree.insert('', 'end', iid=f['id'], values=(f['severity'], f['title'], f['source'], f['confidence']))
        if selected and self.findings_tree.exists(selected[0]): self.findings_tree.selection_set(selected[0])

    def selected_finding(self):
        sel = self.findings_tree.selection()
        return next((f for f in self.case['findings'] if sel and f['id'] == sel[0]), None) if self.case else None

    def show_finding(self, event=None):
        f = self.selected_finding()
        if not f: return
        text = f"{f['title']}\n{f['severity']} priority · {f['confidence']} confidence\n\n{f['summary']}\n\nRecommended action: {f['remediation']}\n\n"
        for e in f['evidence']:
            text += f"Source: {e['provider']} · {e['timestamp']}\nReference: {e.get('reference') or 'Local observation'}\nPath: " + ' → '.join(t['value'] for t in e['pivot_path']) + '\n\n'
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('end', text)
        self.detail.configure(state='disabled')

    def raw_evidence(self):
        f = self.selected_finding()
        if not f: return
        win = tk.Toplevel(self)
        win.title('Raw evidence · ' + f['title'])
        win.geometry('800x550')
        text = self.text_widget(win)
        text.pack(fill='both', expand=True)
        text.insert('end', json.dumps(f, indent=2, ensure_ascii=False))
        text.configure(state='disabled')

    def refresh_cases(self):
        self.cases_tree.delete(*self.cases_tree.get_children())
        cases, errors = self.store.list()
        self.case_index = {c['id']: c for c in cases}
        for c in cases: self.cases_tree.insert('', 'end', iid=c['id'], values=(c['name'], c['client'], len(c['findings']), 'Archived' if c['archived'] else 'Active', c['updated']))
        if errors: self.status.set(f'{len(errors)} unreadable case files; originals preserved.')

    def open_selected_case(self):
        if self.busy(): return
        sel = self.cases_tree.selection()
        if not sel: return
        self.case = self.case_index[sel[0]]
        for scan in self.case['scans']:
            if scan['status'] == 'RUNNING':
                scan['status'] = 'INTERRUPTED'
                scan.setdefault('warnings', []).append('Previous session ended before completion.')
        self.refresh()
        self.show_page('Investigation')

    def import_case(self):
        if self.busy(): return
        path = filedialog.askopenfilename(filetypes=[('SPECTRA case', '*.json')])
        if not path: return
        try:
            case = self.store.load(path)
            case['id'] = str(uuid.uuid4())
            self.store.save(case)
            self.case = case
            self.refresh()
            self.refresh_cases()
        except (ValueError, OSError, KeyError, TypeError): messagebox.showerror('Import failed', 'The selected file is not a valid SPECTRA case.')

    def export_case(self):
        if not self.case: return
        path = filedialog.asksaveasfilename(defaultextension='.json', initialfile='SPECTRA-case-' + self.case['id'][:8] + '.json')
        if path:
            try: atomic_json(path, self.case)
            except OSError: messagebox.showerror('Export failed', 'The destination is not writable.')

    def archive_case(self):
        if self.busy(): return
        sel = self.cases_tree.selection()
        if not sel: return
        c = self.case_index[sel[0]]
        c['archived'] = not c['archived']
        self.store.save(c)
        if self.case and self.case['id'] == c['id']: self.case = c
        self.refresh_cases()

    def draw_graph(self):
        self.canvas.delete('all')
        if not self.case or not self.case['findings']:
            self.canvas.create_text(320, 180, text='Run an investigation to build the evidence graph.', fill=MUTED, font=('Segoe UI', 13))
            return
        findings = [f for f in self.case['findings'] if not self.graph_high.get() or f['confidence'] != 'LOW']
        nodes = {}
        for f in findings:
            nodes[f['subject']['id']] = f['subject']
            nodes[f['object']['id']] = f['object']
        count, positions = len(nodes), {}
        radius = max(150, count * 22)
        cx, cy = max(self.canvas.winfo_width()/2, radius + 100), radius + 80
        for i, (nid, node) in enumerate(nodes.items()):
            angle = 2*math.pi*i/max(count, 1)
            positions[nid] = (cx + radius*math.cos(angle), cy + radius*math.sin(angle))
        for f in findings:
            a, b = positions[f['subject']['id']], positions[f['object']['id']]
            if a != b:
                self.canvas.create_line(*a, *b, fill='#36576e', arrow='last')
                self.canvas.create_text((a[0]+b[0])/2, (a[1]+b[1])/2, text=f['relation'], fill='#7e99af', font=('Segoe UI', 8))
        for nid, node in nodes.items():
            x, y = positions[nid]
            tag = 'node_' + nid
            self.canvas.create_oval(x-12, y-12, x+12, y+12, fill=ACCENT, outline='', tags=(tag,))
            self.canvas.create_text(x, y+29, text=node['value'][:55], fill=TEXT, width=210, font=('Segoe UI', 9), tags=(tag,))
            self.canvas.tag_bind(tag, '<ButtonRelease-1>', lambda e, n=node: self.node_selected(n))
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def node_selected(self, node):
        self.graph_selection = node
        related = [f for f in self.case['findings'] if node['id'] in (f['subject']['id'], f['object']['id'])]
        self.graph_detail.set(node['type'] + ' · ' + node['value'] + f' · {len(related)} related findings')
        win = tk.Toplevel(self)
        win.title('Node evidence')
        win.geometry('780x520')
        text = self.text_widget(win)
        text.pack(fill='both', expand=True)
        text.insert('end', node['type'] + ' · ' + node['value'] + '\n\n')
        for f in related:
            text.insert('end', f['title'] + ' · ' + f['confidence'] + '\n' + f['summary'] + '\n')
            for e in f['evidence']:
                text.insert('end', e['provider'] + ' · ' + e['timestamp'] + '\n' + e['reference'] + '\nPath: ' + ' → '.join(t['value'] for t in e['pivot_path']) + '\n\n')
        text.configure(state='disabled')

    def add_graph_target(self):
        if self.busy() or not self.case or not getattr(self, 'graph_selection', None): return
        node = self.graph_selection
        kind = {'PERSON': 'Name', 'PROFILE': 'URL'}.get(node['type'], node['type'])
        try:
            t = target(node['value'], kind)
            if t not in self.case['targets']: self.case['targets'].append(t)
            self.save_case()
            self.refresh()
            self.show_page('Investigation')
        except ValueError:
            messagebox.showinfo('Not a scan target', 'This node is evidence rather than a supported target type.')

    def zoom_graph(self, factor):
        self.canvas.scale('all', 0, 0, factor, factor)
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def generate_report(self):
        if not self.require_case(): return
        name = 'SPECTRA-' + self.case['id'][:8] + '-' + str(time.time_ns()) + '.html'
        path = self.store.root / 'reports' / name
        try:
            path.write_text(report_html(self.case), encoding='utf-8')
            self.case['reports'].append({'name': name, 'created': now()})
            self.save_case()
            self.refresh_reports()
            self.status.set('Report saved: ' + name)
            webbrowser.open(path.as_uri())
        except OSError: messagebox.showerror('Report failed', 'Could not write the report to the reports folder.')

    def refresh_reports(self):
        self.reports_tree.delete(*self.reports_tree.get_children())
        if self.case:
            for i, r in enumerate(self.case['reports']): self.reports_tree.insert('', 'end', iid=str(i), values=(r['name'], r['created']))

    def open_report(self):
        sel = self.reports_tree.selection()
        if not sel or not self.case: return
        name = Path(self.case['reports'][int(sel[0])]['name']).name
        path = self.store.root / 'reports' / name
        if path.is_file(): webbrowser.open(path.as_uri())
        else: messagebox.showinfo('Report unavailable', 'The report is not in this installation. Generate it again from the case evidence.')

    def refresh_connectors(self):
        self.connectors_tree.delete(*self.connectors_tree.get_children())
        for name, types, access, description in CATALOG:
            enabled = self.settings.get('spiderfoot_enabled') if name == 'SpiderFoot' else name in self.settings.get('connectors', [])
            state = self.connector_states.get(name, 'READY' if name == 'Image' else 'NOT CHECKED')
            if not enabled: state = 'DISABLED'
            elif name in ('Shodan', 'HIBP') and not self.settings.get(name.lower() + '_api_key'): state = 'NOT CONFIGURED'
            self.connectors_tree.insert('', 'end', values=(name, access, state, types, description))

    def save_settings(self):
        try:
            settings = {k: v.get() for k, v in self.setting_vars.items()}
            for key in ('pivot_depth', 'timeout', 'retries'):
                settings[key] = int(settings[key])
                if settings[key] < (1 if key == 'timeout' else 0): raise ValueError()
            settings['connectors'] = [k for k, v in self.source_vars.items() if v.get()]
            settings['auto_pivot'] = self.pivot_value.get()
            self.store.save_settings(settings)
            self.settings = settings
            self.status.set('Settings saved locally; applied to the next investigation')
            self.refresh_connectors()
        except (ValueError, OSError): messagebox.showerror('Settings not saved', 'Use nonnegative depth/retries and a positive timeout; verify the config folder is writable.')

    def check_engine(self):
        if self.busy(): return
        def work():
            try:
                self.engine.ensure(self.settings.get('spiderfoot_url', ''))
                result = 'READY'
            except Exception: result = 'UNAVAILABLE — check bundle or URL'
            self.events.put(('engine_status', result))
        threading.Thread(target=work, daemon=True).start()

    def restart_engine(self):
        if self.busy(): return
        self.engine.close()
        self.engine = Engine(self.store.root)
        self.check_engine()

    def password_dialog(self):
        if self.busy() or not self.require_case(): return
        win = tk.Toplevel(self)
        win.title('Private password exposure check')
        win.geometry('580x300')
        win.configure(bg=BG)
        win.transient(self)
        ttk.Label(win, text='Only a SHA-1 prefix is sent to HIBP. The password is never saved.', wraplength=530).pack(padx=24, pady=20)
        value = tk.StringVar()
        ttk.Entry(win, textvariable=value, show='•').pack(fill='x', padx=24)
        result = tk.StringVar(value='')
        ttk.Label(win, textvariable=result, wraplength=530).pack(padx=24, pady=18)
        case_id = self.case['id']
        def finished(r):
            if win.winfo_exists():
                button.configure(state='normal')
                result.set(('Known exposed password: ' + str(r['count']) + ' observations.' if r.get('exposed') else 'No match in the accessible corpus.') if r['status'] == 'ok' else r.get('message', 'Enter a password.'))
            if r['status'] == 'ok' and self.case and self.case['id'] == case_id:
                original = {'type': 'PASSWORD_CHECK', 'value': 'Client-supplied password (not retained)'}
                raw = dict(r, summary='Known exposed password.' if r['exposed'] else 'No match found; absence does not establish safety.')
                f = finding('Password exposure check', 'HIBP Pwned Passwords', original, raw, severity='HIGH' if r['exposed'] else 'INFO', remediation='Use a unique password and enable MFA. Replace exposed passwords immediately.')
                f['id'] = uuid.uuid4().hex
                merge_finding(self.case, f)
                self.save_case()
                self.refresh()
        def check():
            password = value.get()
            value.set('')
            button.configure(state='disabled')
            result.set('Checking…')
            def work(secret): self.events.put(('password', (finished, pwned_password_check(secret))))
            threading.Thread(target=work, args=(password,), daemon=True).start()
        button = ttk.Button(win, text='Check exposure', command=check, style='Accent.TButton')
        button.pack(pady=8)
        win.grab_set()

    def on_close(self):
        if self.busy():
            self.closing = True
            self.stop_scan()
            self.status.set('Stopping and saving evidence before closing…')
        else:
            self.save_case()
            self.engine.close()
            self.destroy()

    def destroy(self):
        # Cancel timers before removing their Tcl commands, including when tests
        # open a second root in the same process after closing the first.
        for callback in self.tk.call('after', 'info'):
            try:
                self.after_cancel(callback)
            except tk.TclError:
                pass
        super().destroy()


def main():
    import sys
    smoke = '--smoke-test' in sys.argv
    if smoke:
        import tempfile
        from PIL import Image
        with tempfile.TemporaryDirectory(prefix='spectra-gui-smoke-') as folder:
            app = SpectraApp(start_engine=False, root=folder)
            errors = []
            app.report_callback_exception = lambda *args: errors.append(str(args))
            try:
                image = Path(folder) / 'synthetic.png'
                Image.new('RGB', (32, 24), '#43d9c0').save(image)
                app.case = app.store.create('Smoke test', '', 'Synthetic local image')
                app.case['targets'].append(target(str(image), 'Image'))
                app.run_scan()
                deadline = time.monotonic() + 10
                while app.busy() and time.monotonic() < deadline:
                    app.update()
                    time.sleep(.01)
                if app.busy() or not app.case['findings']:
                    raise RuntimeError('Packaged image scan did not complete')
                for page in app.pages:
                    app.show_page(page)
                    app.update()
                if errors: raise RuntimeError('GUI callback errors: ' + str(errors))
                report_html(app.case)
                app.store.load(Path(folder) / 'cases' / (app.case['id'] + '.json'))
            finally:
                app.on_close()
        return
    app = SpectraApp()
    app.mainloop()


if __name__ == '__main__': main()

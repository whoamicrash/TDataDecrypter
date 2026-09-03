import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from .constants import APP_TITLE
from .core import TDataDecrypter, locate_tdata
from .i18n import cur_lang, load_saved_lang, save_lang_cfg, set_lang, tr
from .keys import (extract_local_key, find_john, john_cmd, john_hash,
                   john_show, john_supports_telegram, no_window)
from .ui import Options


def run_gui(demo=False):
    import tkinter as tk
    import tkinter.font as tkfont
    import queue
    import subprocess
    from tkinter import ttk, filedialog, messagebox

    BG = '#171922'
    PANEL = '#1f2230'
    PANEL2 = '#2a2e40'
    FG = '#e8eaf2'
    DIM = '#8b91a7'
    ACCENT = '#4f8cff'
    OK = '#4fd08a'
    WARN = '#f5b04c'
    ERR = '#f56a6a'
    ENTRY_BG = '#12141c'
    LOG_BG = '#101219'

    def pick_lang(parent=None):
        own = parent is None
        w = tk.Tk() if own else tk.Toplevel(parent)
        w.title(APP_TITLE)
        w.configure(bg=BG)
        w.resizable(False, False)
        w.geometry('320x150')
        choice = {}

        def go(lang):
            choice['lang'] = lang
            w.destroy()

        tk.Label(w, text='Выберите язык / Select language', bg=BG, fg=FG,
                 font=('Segoe UI', 11, 'bold')).pack(pady=(26, 16))
        brow = tk.Frame(w, bg=BG)
        brow.pack()
        for lang, name in (('ru', 'Русский'), ('en', 'English')):
            tk.Button(brow, text=name, command=lambda l=lang: go(l),
                      bg=PANEL2, fg=FG, activebackground=ACCENT,
                      activeforeground='#ffffff', relief='flat',
                      font=('Segoe UI', 10, 'bold'), width=12, pady=6,
                      cursor='hand2').pack(side='left', padx=8)
        w.protocol('WM_DELETE_WINDOW', lambda: go('ru'))
        if own:
            w.mainloop()
        else:
            w.transient(parent)
            w.grab_set()
            parent.wait_window(w)
        return choice.get('lang') or 'ru'

    env_lang = os.environ.get('TDATADECRYPTER_LANG')
    if env_lang in ('ru', 'en'):
        lang = env_lang
    else:
        lang = load_saved_lang()
        if not lang:
            lang = pick_lang()
            save_lang_cfg(lang)
    set_lang(lang)

    class GuiUI:

        def __init__(self):
            self.q = queue.Queue()
            self.cancelled = False

        def log(self, msg, level='info'):
            self.q.put(('log', level, msg))

        def progress(self, frac, note=''):
            self.q.put(('prog', frac, note))

        def stage(self, name):
            self.q.put(('stage', name))

    class App:
        def __init__(self, root):
            self.root = root
            self.gui_ui = GuiUI()
            self.worker = None
            self.john_thread = None
            self.john_proc = None
            self.john_cancel = False
            self.last_out = None
            self.run_started_at = None
            self._build()
            self.root.after(60, self._poll)


        def _build(self):
            r = self.root
            r.title(APP_TITLE)
            r.configure(bg=BG)
            r.geometry('960x700')
            r.minsize(880, 640)

            style = ttk.Style(r)
            style.theme_use('clam')
            style.configure('.', background=PANEL, foreground=FG, borderwidth=0)
            style.configure('TFrame', background=PANEL)
            style.configure('Card.TFrame', background=PANEL, relief='flat')
            style.configure('TLabel', background=PANEL, foreground=FG)
            style.configure('Dim.TLabel', background=PANEL, foreground=DIM)
            style.configure('TButton', background=PANEL2, foreground=FG,
                            borderwidth=0, focusthickness=1, padding=(14, 8))
            style.map('TButton', background=[('active', '#343952')])
            style.configure('Accent.TButton', background=ACCENT, foreground='#ffffff',
                            padding=(26, 10), font=('Segoe UI', 10, 'bold'))
            style.map('Accent.TButton',
                      background=[('disabled', '#33507e'), ('active', '#6b9dff')])
            style.configure('Danger.TButton', background='#8c3a3a', foreground='#ffffff',
                            padding=(18, 8))
            style.map('Danger.TButton',
                      background=[('disabled', '#4a2c2c'), ('active', '#a84848')])
            style.configure('TCheckbutton', background=PANEL, foreground=FG,
                            focuscolor=PANEL, padding=(2, 2))
            style.map('TCheckbutton', background=[('active', PANEL)],
                      foreground=[('disabled', DIM)])
            style.configure('TEntry', fieldbackground=ENTRY_BG, foreground=FG,
                            insertcolor=FG, bordercolor=PANEL2, lightcolor=PANEL2,
                            darkcolor=PANEL2, padding=(8, 6))
            style.configure('Horizontal.TProgressbar', troughcolor=ENTRY_BG,
                            background=ACCENT, bordercolor=BG, lightcolor=ACCENT,
                            darkcolor=ACCENT, thickness=10)
            style.configure('Vertical.TScrollbar', troughcolor=LOG_BG,
                            background=PANEL2, bordercolor=LOG_BG,
                            arrowcolor=DIM, relief='flat')

            mono = 'Consolas' if 'Consolas' in tkfont.families() else 'Courier New'

            head = tk.Frame(r, bg=BG)
            head.pack(fill='x', padx=22, pady=(16, 8))
            tk.Label(head, text='TDataDecrypter', bg=BG, fg=FG,
                     font=('Segoe UI', 17, 'bold')).pack(side='left')
            self.lang_btn = tk.Button(head, text=cur_lang().upper(),
                                      command=self._switch_lang, bg=BG, fg=DIM,
                                      activebackground=BG, activeforeground=FG,
                                      relief='flat', font=('Segoe UI', 9, 'bold'),
                                      cursor='hand2')
            self.lang_btn.pack(side='right')

            card = tk.Frame(r, bg=PANEL, highlightthickness=1,
                            highlightbackground='#2c3044')
            card.pack(fill='x', padx=22, pady=6)

            self.var_tdata = tk.StringVar()
            self.var_out = tk.StringVar()
            self.var_pass = tk.StringVar()
            self.opt_sort = tk.BooleanVar(value=True)
            self.opt_merge = tk.BooleanVar(value=True)
            self.opt_clean = tk.BooleanVar(value=True)
            self.opt_raw = tk.BooleanVar(value=True)
            self.opt_staging = tk.BooleanVar(value=False)

            pad = dict(padx=14, pady=7)
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', **pad)
            self.lbl_tdata = tk.Label(row, text=tr('fld_tdata'), bg=PANEL, fg=FG,
                                      width=13, anchor='w')
            self.lbl_tdata.pack(side='left')
            ttk.Entry(row, textvariable=self.var_tdata).pack(
                side='left', fill='x', expand=True, padx=(4, 8))
            self.btn_browse_t = ttk.Button(row, text=tr('browse'),
                                           command=self._pick_tdata, width=9)
            self.btn_browse_t.pack(side='left')

            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', padx=14, pady=(0, 7))
            self.lbl_out = tk.Label(row, text=tr('fld_out'), bg=PANEL, fg=FG,
                                    width=13, anchor='w')
            self.lbl_out.pack(side='left')
            ttk.Entry(row, textvariable=self.var_out).pack(
                side='left', fill='x', expand=True, padx=(4, 8))
            self.btn_browse_o = ttk.Button(row, text=tr('browse'),
                                           command=self._pick_out, width=9)
            self.btn_browse_o.pack(side='left')

            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', padx=14, pady=(0, 10))
            self.lbl_pass = tk.Label(row, text=tr('fld_pass'), bg=PANEL, fg=DIM,
                                     width=13, anchor='w')
            self.lbl_pass.pack(side='left')
            ttk.Entry(row, textvariable=self.var_pass, show='•').pack(
                side='left', fill='x', expand=True, padx=(4, 8))
            self.btn_john = ttk.Button(row, text=tr('btn_john'),
                                       command=self._john_dialog, width=21)
            self.btn_john.pack(side='left')

            card2 = tk.Frame(r, bg=PANEL, highlightthickness=1,
                             highlightbackground='#2c3044')
            card2.pack(fill='x', padx=22, pady=6)
            opts = [
                ('opt_sort', self.opt_sort),
                ('opt_merge', self.opt_merge),
                ('opt_clean', self.opt_clean),
                ('opt_raw', self.opt_raw),
                ('opt_staging', self.opt_staging),
            ]
            orow = tk.Frame(card2, bg=PANEL)
            orow.pack(fill='x', padx=14, pady=(10, 0))
            orow2 = tk.Frame(card2, bg=PANEL)
            orow2.pack(fill='x', padx=14, pady=(6, 10))
            self.checks = []
            for i, (key, var) in enumerate(opts):
                parent = orow if i < 3 else orow2
                cb = ttk.Checkbutton(parent, text=tr(key), variable=var)
                cb.pack(side='left', padx=(0, 16))
                self.checks.append((cb, key))

            act = tk.Frame(r, bg=BG)
            act.pack(fill='x', padx=22, pady=(10, 4))
            self.btn_start = ttk.Button(act, text=tr('btn_start'), style='Accent.TButton',
                                        command=self._start)
            self.btn_start.pack(side='left')
            self.btn_cancel = ttk.Button(act, text=tr('btn_cancel'), style='Danger.TButton',
                                         command=self._cancel, state='disabled')
            self.btn_cancel.pack(side='left', padx=10)
            self.btn_open = ttk.Button(act, text=tr('btn_open'),
                                       command=self._open_out, state='disabled')
            self.btn_open.pack(side='left')
            self.stage_lbl = tk.Label(act, text=tr('ready'), bg=BG, fg=DIM,
                                      font=('Segoe UI', 10))
            self.stage_lbl.pack(side='right')

            self.pbar = ttk.Progressbar(r, mode='determinate', maximum=1.0, value=0)
            self.pbar.pack(fill='x', padx=22, pady=(2, 8))

            logf = tk.Frame(r, bg=LOG_BG, highlightthickness=1,
                            highlightbackground='#2c3044')
            logf.pack(fill='both', expand=True, padx=22, pady=(0, 6))
            self.log_txt = tk.Text(logf, bg=LOG_BG, fg=FG, wrap='word',
                                   font=(mono, 9), relief='flat',
                                   state='disabled', padx=12, pady=10,
                                   insertbackground=FG)
            sb = ttk.Scrollbar(logf, command=self.log_txt.yview)
            self.log_txt.configure(yscrollcommand=sb.set)
            sb.pack(side='right', fill='y')
            self.log_txt.pack(side='left', fill='both', expand=True)
            for tag, color, bold in (('ok', OK, False), ('warn', WARN, False),
                                     ('err', ERR, True), ('info', FG, False),
                                     ('dim', DIM, False), ('stage', ACCENT, True)):
                self.log_txt.tag_configure(tag, foreground=color,
                                           font=(mono, 9, 'bold') if bold else (mono, 9))

            r.protocol('WM_DELETE_WINDOW', self._on_close)
            self._log(f"{APP_TITLE}: {tr('banner')}", 'stage')
            self._log(tr('hint'), 'dim')

        def _apply_lang(self):
            self.lbl_tdata.configure(text=tr('fld_tdata'))
            self.lbl_out.configure(text=tr('fld_out'))
            self.lbl_pass.configure(text=tr('fld_pass'))
            self.btn_browse_t.configure(text=tr('browse'))
            self.btn_browse_o.configure(text=tr('browse'))
            self.btn_john.configure(text=tr('btn_john'))
            for cb, key in self.checks:
                cb.configure(text=tr(key))
            self.btn_start.configure(text=tr('btn_start'))
            self.btn_cancel.configure(text=tr('btn_cancel'))
            self.btn_open.configure(text=tr('btn_open'))
            self.lang_btn.configure(text=cur_lang().upper())
            if not self._busy():
                self.stage_lbl.configure(text=tr('ready'))

        def _busy(self):
            return bool((self.worker and self.worker.is_alive()) or
                        (self.john_thread and self.john_thread.is_alive()))

        def _switch_lang(self):
            if self._busy():
                return
            new = pick_lang(self.root)
            if new and new != cur_lang():
                set_lang(new)
                save_lang_cfg(new)
                self._apply_lang()
                self._log(tr('lang_switched',
                             name={'ru': 'Русский', 'en': 'English'}[new]), 'dim')


        def _pick_tdata(self):
            p = filedialog.askdirectory(title=tr('ttl_tdata'))
            if p:
                self.var_tdata.set(p)
                if not self.var_out.get():
                    self.var_out.set(os.path.join(os.path.dirname(p) or p,
                                                  'tdata_recovered'))

        def _pick_out(self):
            p = filedialog.askdirectory(title=tr('ttl_out'))
            if p:
                self.var_out.set(p)

        def _start(self, clear_log=True):
            tdata = self.var_tdata.get().strip()
            out = self.var_out.get().strip()
            if not tdata or not os.path.isdir(tdata):
                messagebox.showerror(tr('err_no_tdata'), tr('err_no_tdata_msg'))
                return
            if not out:
                messagebox.showerror(tr('err_no_out'), tr('err_no_out_msg'))
                return
            if os.path.isdir(out) and os.listdir(out):
                if not messagebox.askyesno(
                        tr('ask_overwrite'),
                        tr('ask_overwrite_msg').format(out=out)):
                    return
            opts = Options()
            opts.sort_media = self.opt_sort.get()
            opts.merge_videos = self.opt_merge.get()
            opts.clean_texts = self.opt_clean.get()
            opts.raw_dump = self.opt_raw.get()
            opts.keep_staging = self.opt_staging.get()

            if clear_log:
                self.log_txt.configure(state='normal')
                self.log_txt.delete('1.0', 'end')
                self.log_txt.configure(state='disabled')
            self.btn_start.configure(state='disabled')
            self.btn_cancel.configure(state='normal')
            self.btn_open.configure(state='disabled')
            self.btn_john.configure(state='disabled')
            self.lang_btn.configure(state='disabled')
            self.pbar.configure(value=0)
            self.run_started_at = time.time()
            self.last_out = out
            self._log(tr('log_start').format(tdata=tdata), 'stage')

            def worker():
                try:
                    app = TDataDecrypter(tdata, out, self.var_pass.get(), opts,
                                         self.gui_ui)
                    ok = app.run()
                    self.gui_ui.q.put(
                        ('done', ok, (not ok) and app.local_key is None))
                except Exception as e:
                    self.gui_ui.q.put(
                        ('log', 'err', tr('internal_err').format(e=e)))
                    self.gui_ui.q.put(('done', False, False))

            self.worker = threading.Thread(target=worker, daemon=True)
            self.worker.start()

        def _cancel(self):
            if self.john_thread and self.john_thread.is_alive():
                self.john_cancel = True
                self.stage_lbl.configure(text=tr('cancelling'))
                self.btn_cancel.configure(state='disabled')
                if self.john_proc and self.john_proc.poll() is None:
                    try:
                        self.john_proc.kill()
                    except Exception:
                        pass
                return
            if self.worker and self.worker.is_alive():
                self.gui_ui.cancelled = True
                self.stage_lbl.configure(text=tr('cancelling'))
                self.btn_cancel.configure(state='disabled')

        def _open_out(self):
            path = self.last_out
            if path and os.path.isdir(path):
                try:
                    if sys.platform.startswith('win'):
                        os.startfile(path)
                    elif sys.platform == 'darwin':
                        subprocess.Popen(['open', path])
                    else:
                        subprocess.Popen(['xdg-open', path])
                except Exception as e:
                    messagebox.showerror(tr('open_fail'), str(e))

        def _on_close(self):
            if self._busy():
                if not messagebox.askyesno(tr('ask_exit'), tr('ask_exit_msg')):
                    return
                self.gui_ui.cancelled = True
                self.john_cancel = True
                if self.john_proc and self.john_proc.poll() is None:
                    try:
                        self.john_proc.kill()
                    except Exception:
                        pass
                self.root.after(300, self.root.destroy)
            else:
                self.root.destroy()


        def _poll(self):
            try:
                while True:
                    item = self.gui_ui.q.get_nowait()
                    kind = item[0]
                    if kind == 'log':
                        self._log(item[2], item[1])
                    elif kind == 'prog':
                        frac, note = item[1], item[2]
                        self.pbar.configure(value=max(0.0, min(1.0, frac)))
                        pct = int(frac * 100)
                        if note:
                            self.stage_lbl.configure(text=f'{pct}%  ·  {note}')
                        else:
                            self.stage_lbl.configure(text=f'{pct}%')
                    elif kind == 'stage':
                        self._log(f'— {item[1]} —', 'stage')
                        self.stage_lbl.configure(text=item[1])
                    elif kind == 'john_done':
                        self._on_john_done(item[1], item[2],
                                           item[3] if len(item) > 3 else None)
                    elif kind == 'done':
                        self._on_done(item[1], item[2] if len(item) > 2 else False)
            except queue.Empty:
                pass
            self.root.after(60, self._poll)

        def _on_done(self, ok, pass_fail=False):
            self.btn_start.configure(state='normal')
            self.btn_cancel.configure(state='disabled')
            self.lang_btn.configure(state='normal')
            self.btn_john.configure(state='normal')
            if ok:
                self.pbar.configure(value=1.0)
                self.stage_lbl.configure(text=tr('done_lbl'))
                self._log(tr('log_done').format(out=self.last_out), 'ok')
                if self.run_started_at:
                    self._log(tr('log_time').format(
                        t=f'{time.time() - self.run_started_at:.1f}'), 'dim')
                self.btn_open.configure(state='normal')
                try:
                    rep = os.path.join(self.last_out, 'report.txt')
                    if os.path.isfile(rep):
                        with open(rep, encoding='utf-8') as f:
                            tail = f.read().split(tr('rep_total'))[-1].strip()
                        if tail:
                            self._log('')
                            self._log(tr('rep_total'), 'stage')
                            for line in tail.splitlines():
                                if line.strip():
                                    self._log('  ' + line.strip(), 'ok')
                except Exception:
                    pass
                messagebox.showinfo(
                    tr('info_done'), tr('info_done_msg').format(out=self.last_out))
            else:
                self.stage_lbl.configure(text=tr('stopped_lbl'))
                self._log(tr('log_stopped'), 'warn')
                if pass_fail:
                    act = self._ask_pass_fail(bool(self.var_pass.get()))
                    if act == 'retry':
                        pw = messagebox.askstring(
                            tr('ask_pass_ttl'), tr('ask_pass_lbl'), show='•')
                        if pw is not None:
                            self.var_pass.set(pw)
                            self._start()
                    elif act == 'john':
                        self._john_dialog()

        def _ask_pass_fail(self, has_pass):
            w = tk.Toplevel(self.root)
            w.title(tr('wrong_pass_ttl') if has_pass else tr('ask_pass'))
            w.configure(bg=BG)
            w.resizable(False, False)
            w.transient(self.root)
            w.grab_set()
            choice = {}

            def go(v):
                choice['v'] = v
                w.destroy()

            msg = tr('wrong_pass_msg') if has_pass else tr('ask_pass_msg')
            tk.Label(w, text=msg, bg=BG, fg=FG, wraplength=440,
                     justify='left', font=('Segoe UI', 10)).pack(
                         padx=20, pady=(18, 14))
            brow = tk.Frame(w, bg=BG)
            brow.pack(padx=16, pady=(0, 18))
            for text, v in ((tr('ask_pass_btn_retry'), 'retry'),
                            (tr('ask_pass_btn_john'), 'john'),
                            (tr('btn_cancel'), None)):
                tk.Button(brow, text=text, command=lambda vv=v: go(vv),
                          bg=PANEL2, fg=FG, activebackground=ACCENT,
                          activeforeground='#ffffff', relief='flat',
                          font=('Segoe UI', 9, 'bold'), padx=14, pady=6,
                          cursor='hand2').pack(side='left', padx=6)
            w.protocol('WM_DELETE_WINDOW', lambda: go(None))
            self.root.wait_window(w)
            return choice.get('v')

        def _john_dialog(self):
            if self._busy():
                return
            tdata = self.var_tdata.get().strip()
            if not tdata or not os.path.isdir(tdata):
                messagebox.showerror(tr('err_no_tdata'), tr('err_no_tdata_msg'))
                return
            td = locate_tdata(tdata)
            if not td:
                messagebox.showerror(tr('err_no_tdata'), tr('tdata_not_found'))
                return
            key, _msg = extract_local_key(td, b'')
            if key is not None:
                if messagebox.askyesno(tr('john_nopass'), tr('john_nopass_msg')):
                    self._start()
                return
            jh = john_hash(td)
            if not jh:
                messagebox.showerror(tr('john_nohash'), tr('john_nohash_msg'))
                return
            john = find_john()
            if not john:
                messagebox.showerror(tr('john_nojohn'), tr('john_nojohn_msg'))
                return
            if not john_supports_telegram(john):
                messagebox.showerror(tr('john_nofmt'), tr('john_nofmt_msg'))
                return
            self._john_dlg(td, jh, john)

        def _john_dlg(self, td, jh, john):
            w = tk.Toplevel(self.root)
            w.title(tr('john_dlg_title'))
            w.configure(bg=BG)
            w.resizable(False, False)
            w.transient(self.root)
            w.grab_set()

            tk.Label(w, text=tr('john_dlg_msg'), bg=BG, fg=DIM,
                     wraplength=520, justify='left',
                     font=('Segoe UI', 9)).pack(padx=20, pady=(16, 10))

            var_wl = tk.StringVar()
            var_mask = tk.StringVar()
            var_rules = tk.BooleanVar(value=False)

            card = tk.Frame(w, bg=PANEL)
            card.pack(fill='x', padx=16)

            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', padx=12, pady=(10, 0))
            tk.Label(row, text=tr('john_wordlist'), bg=PANEL, fg=FG,
                     width=9, anchor='w').pack(side='left')
            ttk.Entry(row, textvariable=var_wl).pack(
                side='left', fill='x', expand=True, padx=(4, 6))
            ttk.Button(row, text=tr('browse'), width=8,
                       command=lambda: var_wl.set(
                           filedialog.askopenfilename(
                               title=tr('john_wl_ttl')) or var_wl.get())
                       ).pack(side='left')

            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', padx=12, pady=(8, 0))
            tk.Label(row, text=tr('john_mask'), bg=PANEL, fg=FG,
                     width=9, anchor='w').pack(side='left')
            ttk.Entry(row, textvariable=var_mask).pack(
                side='left', fill='x', expand=True, padx=(4, 8))
            tk.Label(row, text=tr('john_mask_hint'), bg=PANEL, fg=DIM,
                     font=('Segoe UI', 8)).pack(side='left')

            ttk.Checkbutton(card, text=tr('john_rules'),
                            variable=var_rules).pack(
                                anchor='w', padx=12, pady=(8, 4))
            tk.Label(card, text=tr('john_hint_masks'), bg=PANEL, fg=DIM,
                     wraplength=500, justify='left',
                     font=('Segoe UI', 8)).pack(padx=12, pady=(0, 10),
                                                fill='x')

            vals = {}

            def on_start():
                vals['wl'] = var_wl.get().strip()
                vals['mask'] = var_mask.get().strip()
                vals['rules'] = var_rules.get()
                w.destroy()

            brow = tk.Frame(w, bg=BG)
            brow.pack(pady=(4, 16))
            tk.Button(brow, text=tr('john_start_btn'), command=on_start,
                      bg=ACCENT, fg='#ffffff', activebackground='#6b9dff',
                      activeforeground='#ffffff', relief='flat',
                      font=('Segoe UI', 10, 'bold'), padx=18, pady=7,
                      cursor='hand2').pack(side='left', padx=6)
            tk.Button(brow, text=tr('btn_cancel'),
                      command=lambda: w.destroy(), bg=PANEL2, fg=FG,
                      activebackground='#343952', activeforeground=FG,
                      relief='flat', font=('Segoe UI', 9, 'bold'),
                      padx=14, pady=7, cursor='hand2').pack(side='left', padx=6)
            w.protocol('WM_DELETE_WINDOW', w.destroy)
            self.root.wait_window(w)
            if vals:
                self._john_start(td, jh, john, vals['wl'], vals['mask'],
                                 vals['rules'])

        def _john_start(self, td, jh, john, wordlist, mask, rules):
            self.john_cancel = False
            self.btn_start.configure(state='disabled')
            self.btn_john.configure(state='disabled')
            self.btn_cancel.configure(state='normal')
            self.btn_open.configure(state='disabled')
            self.lang_btn.configure(state='disabled')
            self.pbar.configure(mode='indeterminate')
            self.pbar.start(40)
            self.stage_lbl.configure(text=tr('john_run'))
            self.run_started_at = time.time()
            self._log(tr('john_run'), 'stage')
            self._log(tr('john_hash_log', h=jh), 'dim')

            def worker():
                try:
                    self._john_worker(td, jh, john, wordlist, mask, rules)
                except Exception as e:
                    self.gui_ui.q.put(
                        ('log', 'err', tr('john_run_err').format(e=e)))
                    self.gui_ui.q.put(('john_done', None, 'exit', -1))

            self.john_thread = threading.Thread(target=worker, daemon=True)
            self.john_thread.start()

        def _john_worker(self, td, jh, john, wordlist, mask, rules):
            tmp = tempfile.mkdtemp(prefix='tdatajohn')
            hashfile = os.path.join(tmp, 'hash.txt')
            pot = os.path.join(tmp, 'john.pot')
            session = os.path.join(tmp, 'session')
            try:
                with open(hashfile, 'w', encoding='utf-8') as f:
                    f.write(jh + '\n')
                open(pot, 'w', encoding='utf-8').close()
                cmd = john_cmd(john, pot, session, hashfile, wordlist, mask,
                               rules)
                self.gui_ui.q.put(('log', 'dim',
                                   tr('john_cmd_log', cmd=' '.join(cmd))))
                try:
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True,
                        encoding='utf-8', errors='replace', cwd=tmp,
                        **no_window())
                except Exception as e:
                    self.gui_ui.q.put(
                        ('log', 'err', tr('john_run_err').format(e=e)))
                    self.gui_ui.q.put(('john_done', None, 'exit', -1))
                    return
                self.john_proc = proc

                def reader():
                    try:
                        for line in proc.stdout:
                            line = line.rstrip('\r\n')
                            if line:
                                self.gui_ui.q.put(
                                    ('log', 'dim',
                                     tr('john_line', line=line)))
                    except Exception:
                        pass

                rt = threading.Thread(target=reader, daemon=True)
                rt.start()

                found = None
                exit_rc = None
                cancelled = False
                started = time.time()
                last_note = 0.0
                while True:
                    if self.john_cancel:
                        cancelled = True
                        if proc.poll() is None:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        break
                    rc = proc.poll()
                    found = john_show(john, pot, hashfile)
                    if found:
                        if proc.poll() is None:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        break
                    if rc is not None:
                        exit_rc = rc
                        break
                    now = time.time()
                    if now - started - last_note >= 60:
                        last_note = now - started
                        self.gui_ui.q.put(('log', 'dim', tr(
                            'john_elapsed', t=int(last_note) // 60)))
                    time.sleep(1.2)
                rt.join(timeout=3)
                self.john_proc = None

                if cancelled and not found:
                    found = john_show(john, pot, hashfile)
                if found:
                    self.gui_ui.q.put(
                        ('log', 'ok', tr('john_found', pw=found)))
                    key, msg = extract_local_key(td, found.encode('utf-8'))
                    if key is None:
                        self.gui_ui.q.put(
                            ('log', 'err', tr('john_ver_fail', msg=msg)))
                        self.gui_ui.q.put(('john_done', found, 'verfail', None))
                    else:
                        self.gui_ui.q.put(('log', 'ok', tr('john_ver_ok')))
                        self.gui_ui.q.put(('john_done', found, 'ok', None))
                elif cancelled:
                    self.gui_ui.q.put(('john_done', None, 'cancel', None))
                elif exit_rc not in (None, 0):
                    self.gui_ui.q.put(
                        ('log', 'err', tr('john_exit_log', rc=exit_rc)))
                    self.gui_ui.q.put(('john_done', None, 'exit', exit_rc))
                else:
                    self.gui_ui.q.put(('john_done', None, 'notfound', None))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        def _on_john_done(self, pw, status, rc=None):
            self.john_thread = None
            try:
                self.pbar.stop()
            except Exception:
                pass
            self.pbar.configure(mode='determinate', value=0)
            self.btn_start.configure(state='normal')
            self.btn_john.configure(state='normal')
            self.btn_cancel.configure(state='disabled')
            self.lang_btn.configure(state='normal')
            if status == 'ok':
                self.var_pass.set(pw)
                self._log(tr('john_autostart'), 'stage')
                self._start(clear_log=False)
            elif status == 'verfail':
                self.stage_lbl.configure(text=tr('stopped_lbl'))
                messagebox.showerror(
                    tr('john_ver_fail_ttl'),
                    tr('john_ver_fail_msg').format(pw=pw))
            elif status == 'cancel':
                self.stage_lbl.configure(text=tr('ready'))
                self._log(tr('john_stop'), 'warn')
            elif status == 'exit':
                self.stage_lbl.configure(text=tr('stopped_lbl'))
                messagebox.showerror(
                    tr('john_exit_ttl'), tr('john_exit_msg').format(rc=rc))
            else:
                self.stage_lbl.configure(text=tr('ready'))
                self._log(tr('john_none_log'), 'warn')
                messagebox.showwarning(tr('john_none_ttl'), tr('john_none_msg'))

        def _log(self, msg, level='info'):
            tag = level if level in ('ok', 'warn', 'err', 'dim', 'stage') else 'info'
            self.log_txt.configure(state='normal')
            self.log_txt.insert('end', msg + '\n', tag)
            self.log_txt.see('end')
            self.log_txt.configure(state='disabled')

    root = tk.Tk()
    app = App(root)

    if demo:
        app.var_tdata.set(r'C:\Users\user\AppData\Roaming\AyuGram\tdata')
        app.var_out.set(r'D:\recovered\tdata_recovered')
        app.pbar.configure(value=0.47)
        app.stage_lbl.configure(
            text=f"47%  ·  {tr('prog_cache', d=3408, t=7095)}")
        for line, lv in [
            ('[i] ' + tr('tdata_found', path='…\\AyuGram\\tdata'), 'info'),
            (tr('key_ok', name='key_datas', kind='modern', version='5',
                note=tr('key_info_ok', n=2)), 'ok'),
            (tr('self_serialized', n=3), 'ok'),
            (tr('cache_done', rel='user_data/cache', n=5660), 'info'),
            (tr('merged_holes', name='A1B2C3D4E5F6.mp4', filled=25311568,
                total=37951616), 'warn'),
        ]:
            app._log(line, lv)

        def _shot_and_close():
            shot = os.environ.get('TDATADECRYPTER_SHOT')
            if shot:
                try:
                    root.update_idletasks()
                    root.update()
                    from PIL import ImageGrab
                    img = ImageGrab.grab(xdisplay=os.environ.get('DISPLAY', ':0'))
                    img.save(shot)
                except Exception as e:
                    print('screenshot failed:', e)
            root.destroy()

        root.after(1800, _shot_and_close)

    root.mainloop()
    return 0

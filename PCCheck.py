import sys
import os
import re
import time
import subprocess
import ctypes
import hashlib
import json
import urllib.request
import webbrowser
from datetime import datetime, timedelta

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QFrame, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QProgressBar, QAbstractItemView, QMenu, QCheckBox, QLineEdit,
    QStatusBar, QMenuBar, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QColor, QAction

APP_NAME = "PCCheck"
VERSION = "v2.5"
AUTHOR = "hero684k"

VT_CACHE = {}

# ============================================================
def sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def vt_url(path):
    h = sha256(path)
    return f"https://www.virustotal.com/gui/file/{h}" if h else ""

def vt_stats(path):
    if not path or not os.path.exists(path):
        return "—"
    h = sha256(path)
    if not h:
        return "—"
    if h in VT_CACHE:
        return VT_CACHE[h]
    try:
        url = f"https://www.virustotal.com/ui/files/{h}"
        req = urllib.request.Request(url, headers={"User-Agent": "PCCheck/2.5"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8"))
        s = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal, tot = s.get("malicious", 0), sum(s.values())
        res = f"{mal}/{tot}" if tot else "—"
    except:
        res = "—"
    VT_CACHE[h] = res
    return res

def kill(pid):
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=0x08000000)
        return True
    except:
        return False

def props(path):
    if path and os.path.exists(path):
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "properties", path, None, None, 5)
        except:
            d = os.path.dirname(path)
            if os.path.exists(d):
                os.startfile(d)

def open_loc(path):
    if path:
        if os.path.isfile(path):
            os.system(f'explorer /select,"{path}"')
        elif os.path.isdir(path):
            os.startfile(path)

# ============================================================
def get_procs():
    procs = []
    try:
        import psutil
        pd = []
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                i = p.info
                pd.append((i["pid"], i["name"] or "", i["exe"] or ""))
            except: pass

        paths = list(set(p[2] for p in pd if p[2] and os.path.exists(p[2])))
        sm = {}
        for i in range(0, len(paths), 30):
            chunk = paths[i:i+30]
            scr = "; ".join([
                f"$s=Get-AuthenticodeSignature '{p}' -EA 0; "
                f"Write-Output ('{p}@@@' + $s.Status + '@@@' + ($s.SignerCertificate.Subject -replace 'CN=','' -split ',')[0])"
                for p in chunk
            ])
            try:
                r = subprocess.run(["powershell", "-NoProfile", "-Command", scr],
                    capture_output=True, text=True, timeout=60, creationflags=0x08000000)
                for l in r.stdout.splitlines():
                    if "@@@" in l:
                        parts = l.split("@@@")
                        if len(parts) >= 3:
                            sm[parts[0]] = (parts[1], parts[2][:60])
            except: pass

        for pid, name, exe in pd:
            s = sm.get(exe, ("", ""))
            signed = "Yes" if s[0] == "Valid" else ("Bad" if s[0] == "HashMismatch" else "No")
            signer = s[1] if s[1] else "—"
            procs.append({
                "pid": pid, "name": name, "path": exe or "—",
                "signed": signed, "signer": signer, "exe_path": exe
            })
    except: pass
    return procs

def get_reg():
    import winreg
    entries = []
    paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\..\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\..\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\..\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\..\\RunOnce"),
    ]
    bad = ["powershell -enc", "hidden", "bypass", "trojan", "virus", "hack", "inject", "crack", "temp\\"]
    for hive, subkey, loc in paths:
        try:
            k = winreg.OpenKey(hive, subkey)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                    vl = val.lower()
                    disp = name
                    m = re.search(r'([^\\]+)\.exe', val)
                    if m: disp = m.group(1).replace("-", " ").replace("_", " ").title()
                    risk = "Low"
                    if any(kw in vl for kw in bad): risk = "High"
                    elif ".exe" in vl and "program files" not in vl and "windows" not in vl: risk = "Medium"
                    ep = ""
                    m = re.search(r'["\']?([A-Za-z]:\\[^"\']+\.exe)', val)
                    if m: ep = m.group(1)
                    entries.append({
                        "source": loc, "name": disp, "command": val[:200],
                        "risk": risk, "exe_path": ep
                    })
                    i += 1
                except OSError: break
            winreg.CloseKey(k)
        except: pass
    entries.sort(key=lambda x: {"High": 0, "Medium": 1, "Low": 2}[x["risk"]])
    return entries

def get_sch():
    entries = []
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/nh"],
            capture_output=True, text=True, timeout=15, creationflags=0x08000000)
        for line in r.stdout.splitlines():
            parts = line.split('","')
            if len(parts) >= 1:
                name = parts[0].strip('"')
                task = parts[2].strip('"') if len(parts) > 2 else ""
                if name:
                    ep = ""
                    m = re.search(r'["\']?([A-Za-z]:\\[^"\']+\.exe)', task)
                    if m: ep = m.group(1)
                    entries.append({
                        "source": "Scheduler", "name": name[:100],
                        "command": task[:200], "risk": "Low", "exe_path": ep
                    })
    except: pass
    return entries

def get_usb():
    import winreg
    devs = []
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
        i = 0
        while True:
            try:
                did = winreg.EnumKey(k, i)
                sk = winreg.OpenKey(k, did)
                j = 0
                while True:
                    try:
                        ser = winreg.EnumKey(sk, j)
                        dk = winreg.OpenKey(sk, ser)
                        try: friendly = winreg.QueryValueEx(dk, "FriendlyName")[0]
                        except: friendly = did.replace("_", " ")
                        mt = None
                        try: mt = datetime.fromtimestamp(winreg.QueryInfoKey(dk)[2])
                        except: pass
                        devs.append({
                            "name": friendly[:70],
                            "last": mt.strftime("%Y-%m-%d %H:%M:%S") if mt else "—",
                            "first": "—"
                        })
                        winreg.CloseKey(dk)
                        j += 1
                    except OSError: break
                winreg.CloseKey(sk)
                i += 1
            except OSError: break
        winreg.CloseKey(k)
    except: pass
    return devs

def get_rec():
    files = []
    rp = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Microsoft", "Windows", "Recent")
    if os.path.exists(rp):
        for f in os.listdir(rp):
            if f.endswith(".lnk"):
                fp = os.path.join(rp, f)
                try:
                    mt = datetime.fromtimestamp(os.path.getmtime(fp))
                    if (datetime.now() - mt).days < 7:
                        target = ""
                        try:
                            scr = f"$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut('{fp}'); $s.TargetPath"
                            r = subprocess.run(["powershell", "-NoProfile", "-Command", scr],
                                capture_output=True, text=True, timeout=3, creationflags=0x08000000)
                            target = r.stdout.strip()
                        except: pass
                        files.append({
                            "name": f.replace(".lnk", ""),
                            "target": target or "—",
                            "date": mt.strftime("%Y-%m-%d %H:%M:%S"),
                            "path": target
                        })
                except: pass
    files.sort(key=lambda x: x["date"], reverse=True)
    return files[:50]

def get_new():
    sus = []
    cutoff = datetime.now() - timedelta(days=14)
    roots = []
    for d in [os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"),
              os.path.join(os.environ["USERPROFILE"], "AppData", "Local"),
              os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming")]:
        if d and os.path.exists(d): roots.append(d)
    skip = {"windows", "system32", "syswow64", "microsoft", "package cache", ".git", "node_modules", "__pycache__"}
    for root in roots:
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                if dirpath.replace(root, "").count(os.sep) > 3:
                    dirnames.clear(); continue
                dirnames[:] = [d for d in dirnames if d.lower() not in skip]
                for f in filenames:
                    if f.lower().endswith((".exe", ".dll", ".sys")):
                        fp = os.path.join(dirpath, f)
                        try:
                            mt = datetime.fromtimestamp(os.path.getmtime(fp))
                            if mt > cutoff:
                                sus.append({
                                    "name": f, "path": fp,
                                    "date": mt.strftime("%Y-%m-%d %H:%M:%S"),
                                    "exe_path": fp
                                })
                        except: pass
        except: pass
    sus.sort(key=lambda x: x["date"], reverse=True)
    return sus[:100]


class ScanThread(QThread):
    prog = pyqtSignal(str)
    res = pyqtSignal(str, list)
    fin = pyqtSignal()

    def run(self):
        for msg, func, key in [
            ("Scanning processes...", get_procs, "proc"),
            ("Scanning registry...", get_reg, "reg"),
            ("Scanning scheduled tasks...", get_sch, "sch"),
            ("Scanning USB history...", get_usb, "usb"),
            ("Scanning recent files...", get_rec, "rec"),
            ("Scanning new files...", get_new, "new"),
        ]:
            try:
                self.prog.emit(msg)
                self.res.emit(key, func())
            except Exception as e:
                self.prog.emit(f"Error: {e}")
        self.prog.emit("Ready")
        self.fin.emit()


class VTCheckThread(QThread):
    vt_ready = pyqtSignal(str, str, str)
    fin = pyqtSignal()

    def __init__(self, items):
        super().__init__()
        self.items = items

    def run(self):
        for item_id, path in self.items:
            if path:
                stats = vt_stats(path)
                url = vt_url(path)
                self.vt_ready.emit(item_id, stats, url)
                time.sleep(0.5)
        self.fin.emit()


class PCCheckApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {VERSION} — {AUTHOR}")
        self.setMinimumSize(1100, 750)
        self.vt_queue = []
        self._ui()
        self._theme()
        self._anim()

    def _ui(self):
        cw = QWidget(); self.setCentralWidget(cw)
        ml = QVBoxLayout(cw); ml.setContentsMargins(8, 8, 8, 8); ml.setSpacing(6)

        mb = self.menuBar(); mb.setNativeMenuBar(False)
        fm = mb.addMenu("&File")
        fm.addAction("&Scan\tCtrl+S", self._scan)
        fm.addAction("&Export...\tCtrl+E", self._export)
        fm.addSeparator()
        fm.addAction("E&xit", self.close)
        vm = mb.addMenu("&View")
        self.act_ms = QAction("Hide &Microsoft Entries", self); self.act_ms.setCheckable(True); self.act_ms.setChecked(True); self.act_ms.triggered.connect(self._filter)
        vm.addAction(self.act_ms)
        self.act_signed = QAction("Hide &Signed", self); self.act_signed.setCheckable(True); self.act_signed.triggered.connect(self._filter)
        vm.addAction(self.act_signed)
        self.act_vt = QAction("Auto-Check &VirusTotal", self); self.act_vt.setCheckable(True); self.act_vt.setChecked(True)
        vm.addAction(self.act_vt)
        mb.addMenu("&Help").addAction("&About", lambda: self.status_bar.showMessage(f"{APP_NAME} {VERSION} by {AUTHOR}"))

        ff = QFrame(); ff.setFrameStyle(QFrame.Shape.NoFrame)
        fl = QHBoxLayout(ff); fl.setContentsMargins(0, 0, 0, 0); fl.setSpacing(8)
        self.chk_ms = QCheckBox("Hide Microsoft"); self.chk_ms.setChecked(True); self.chk_ms.stateChanged.connect(self._filter)
        fl.addWidget(self.chk_ms)
        self.chk_signed = QCheckBox("Hide Signed"); self.chk_signed.stateChanged.connect(self._filter)
        fl.addWidget(self.chk_signed)
        fl.addStretch()
        fl.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit(); self.filter_edit.setPlaceholderText("Type to filter..."); self.filter_edit.setFixedWidth(200); self.filter_edit.textChanged.connect(self._filter)
        fl.addWidget(self.filter_edit)
        ml.addWidget(ff)

        self.tabs = QTabWidget(); self.tabs.setDocumentMode(True)
        self.proc_tree = self._tree(["PID", "Process Name", "Image Path", "Publisher", "Signed", "VT"])
        self.reg_tree = self._tree(["Registry Path", "Program", "Command", "Risk", "VT"])
        self.sch_tree = self._tree(["Source", "Task Name", "Command", "Risk", "VT"])
        self.usb_tree = self._tree(["Device Name", "Last Connected", "First Connected"])
        self.rec_tree = self._tree(["File Name", "Target", "Date Modified"])
        self.nf_tree = self._tree(["File Name", "Path", "Date Created", "VT"])

        self.tabs.addTab(self._wrap(self.proc_tree), "Processes")
        self.tabs.addTab(self._wrap(self.reg_tree), "Registry")
        self.tabs.addTab(self._wrap(self.sch_tree), "Scheduled")
        self.tabs.addTab(self._wrap(self.usb_tree), "USB")
        self.tabs.addTab(self._wrap(self.rec_tree), "Recent")
        self.tabs.addTab(self._wrap(self.nf_tree), "New Files")
        ml.addWidget(self.tabs)

        self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        self.scan_btn = QPushButton("  SCAN  "); self.scan_btn.setMinimumHeight(28); self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor); self.scan_btn.clicked.connect(self._scan)
        self.status_bar.addPermanentWidget(self.scan_btn)
        self.pbar = QProgressBar(); self.pbar.setVisible(False); self.pbar.setTextVisible(False); self.pbar.setFixedWidth(120); self.pbar.setFixedHeight(12)
        self.status_bar.addPermanentWidget(self.pbar)

    def _tree(self, hdrs):
        t = QTreeWidget(); t.setHeaderLabels(hdrs); t.setRootIsDecorated(False); t.setSortingEnabled(True)
        t.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection); t.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        t.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); t.customContextMenuRequested.connect(self._ctx)
        t.itemDoubleClicked.connect(self._dbl); t.setAlternatingRowColors(True); t.setFont(QFont("Consolas", 10))
        h = t.header(); h.setStretchLastSection(True)
        if len(hdrs) >= 5: h.resizeSection(0, 55); h.resizeSection(1, 130); h.resizeSection(2, 260)
        elif len(hdrs) == 3: h.resizeSection(0, 180); h.resizeSection(1, 300)
        elif len(hdrs) == 2: h.resizeSection(0, 300)
        return t

    def _wrap(self, t):
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(0, 0, 0, 0); l.setSpacing(0); l.addWidget(t)
        return w

    def _filter(self):
        ft = self.filter_edit.text().lower(); hm = self.chk_ms.isChecked(); hs = self.chk_signed.isChecked()
        for tree in [self.proc_tree, self.reg_tree, self.sch_tree, self.usb_tree, self.rec_tree, self.nf_tree]:
            for i in range(tree.topLevelItemCount()):
                item = tree.topLevelItem(i); visible = True
                if ft:
                    texts = [item.text(c).lower() for c in range(tree.columnCount())]
                    if not any(ft in t for t in texts): visible = False
                if hm and tree in (self.reg_tree, self.sch_tree):
                    if "microsoft" in item.text(1).lower() or "microsoft" in item.text(2).lower(): visible = False
                if hs and tree == self.proc_tree:
                    if item.text(4) == "Yes": visible = False
                item.setHidden(not visible)

    def _ctx(self, pos):
        tree = self.sender(); item = tree.itemAt(pos)
        if not item: return
        menu = QMenu(self)
        menu.addAction("Copy Row").triggered.connect(lambda: QApplication.clipboard().setText('\t'.join(item.text(c) for c in range(tree.columnCount()))))
        menu.addSeparator()

        fp = None
        for col in range(tree.columnCount()):
            txt = item.text(col)
            if txt and os.path.exists(txt): fp = txt; break
        if fp:
            menu.addAction("Open File Location").triggered.connect(lambda p=fp: open_loc(p))
            menu.addAction("Properties").triggered.connect(lambda p=fp: props(p))

        vt_col = None
        for col in range(tree.columnCount()):
            if item.text(col).startswith("http"):
                vt_col = item.text(col)
                break
        if vt_col:
            menu.addAction("Open VirusTotal").triggered.connect(lambda u=vt_col: webbrowser.open(u))
        elif fp:
            menu.addAction("Check on VirusTotal").triggered.connect(lambda p=fp: webbrowser.open(vt_url(p)) if vt_url(p) else None)

        pid = item.text(0)
        if pid and pid.isdigit():
            menu.addSeparator()
            menu.addAction("Kill Process").triggered.connect(lambda p=int(pid): self._kill(p))
        menu.exec(tree.viewport().mapToGlobal(pos))

    def _dbl(self, item, col):
        txt = item.text(col)
        if txt.startswith("http"):
            webbrowser.open(txt)
        elif txt and os.path.exists(txt):
            props(txt)

    def _kill(self, pid):
        if kill(pid): self.status_bar.showMessage(f"Process {pid} terminated")
        else: self.status_bar.showMessage(f"Failed to terminate {pid}")

    def _export(self):
        fp, _ = QFileDialog.getSaveFileName(self, "Export", "", "CSV (*.csv)")
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                tree = self.tabs.currentWidget().findChild(QTreeWidget)
                if tree:
                    hdrs = [tree.headerItem().text(c) for c in range(tree.columnCount())]
                    f.write('\t'.join(hdrs) + '\n')
                    for i in range(tree.topLevelItemCount()):
                        item = tree.topLevelItem(i)
                        if not item.isHidden():
                            f.write('\t'.join(item.text(c) for c in range(tree.columnCount())) + '\n')
            self.status_bar.showMessage(f"Exported: {fp}")

    def _theme(self):
        self.setStyleSheet("""
            QMainWindow{background:#F5F5F5}
            QMenuBar{background:#FAFAFA;color:#1A1A1A;border-bottom:1px solid #E0E0E0;padding:1px}
            QMenuBar::item{padding:4px 10px} QMenuBar::item:selected{background:#E8F0FE}
            QMenu{background:#FFF;color:#1A1A1A;border:1px solid #CCC;padding:2px;border-radius:4px}
            QMenu::item{padding:5px 32px 5px 18px} QMenu::item:selected{background:#0078D4;color:#FFF;border-radius:2px}
            QMenu::separator{height:1px;background:#E0E0E0;margin:3px 8px}
            QLabel{color:#1A1A1A;font-size:12px} QCheckBox{color:#1A1A1A;font-size:12px}
            QLineEdit{background:#FFF;color:#1A1A1A;border:1px solid #CCC;border-radius:3px;padding:3px 6px;font-size:12px}
            QLineEdit:focus{border-color:#0078D4}
            QPushButton{background:#F0F0F0;color:#1A1A1A;border:1px solid #CCC;border-radius:3px;padding:5px 14px;font-size:12px}
            QPushButton:hover{background:#E8F0FE;border-color:#0078D4}
            QStatusBar QPushButton{background:#0078D4;color:#FFF;border:none;border-radius:3px;padding:6px 24px;font-weight:bold;font-size:13px}
            QStatusBar QPushButton:hover{background:#005A9E}
            QTabWidget::pane{border:1px solid #CCC;background:#FFF;top:-1px;border-radius:0 0 4px 4px}
            QTabBar::tab{background:#F0F0F0;color:#555;padding:6px 14px;border:1px solid #CCC;border-bottom:none;margin-right:2px;font-size:12px;border-radius:4px 4px 0 0}
            QTabBar::tab:selected{background:#FFF;color:#1A1A1A;font-weight:bold;border-bottom:1px solid #FFF}
            QTabBar::tab:hover{background:#E8F0FE}
            QTreeWidget{background:#FFF;color:#1A1A1A;border:none;font-size:11px;outline:none;alternate-background-color:#F8F8F8}
            QTreeWidget::item{padding:2px 4px;border:none}
            QTreeWidget::item:hover{background:#E8F0FE}
            QTreeWidget::item:selected{background:#0078D4;color:#FFF}
            QHeaderView::section{background:#F5F5F5;color:#1A1A1A;padding:4px 8px;border:none;border-bottom:2px solid #CCC;border-right:1px solid #E0E0E0;font-weight:bold;font-size:11px}
            QScrollBar:vertical{background:#F5F5F5;width:8px;margin:0;border-radius:4px}
            QScrollBar::handle:vertical{background:#C0C0C0;min-height:30px;border-radius:4px}
            QScrollBar::handle:vertical:hover{background:#A0A0A0}
            QScrollBar::add-line:vertical,.QScrollBar::sub-line:vertical{height:0}
            QScrollBar:horizontal{background:#F5F5F5;height:8px;margin:0;border-radius:4px}
            QScrollBar::handle:horizontal{background:#C0C0C0;min-width:30px;border-radius:4px}
            QScrollBar::handle:horizontal:hover{background:#A0A0A0}
            QScrollBar::add-line:horizontal,.QScrollBar::sub-line:horizontal{width:0}
            QStatusBar{background:#FAFAFA;color:#555;border-top:1px solid #E0E0E0;font-size:11px}
            QProgressBar{background:#FFF;border:1px solid #CCC;border-radius:3px}
            QProgressBar::chunk{background:#0078D4;border-radius:2px}
        """)

    def _anim(self):
        self.setWindowOpacity(0)
        a = QPropertyAnimation(self, b"windowOpacity", self)
        a.setDuration(200)
        a.setStartValue(0)
        a.setEndValue(1)
        a.setEasingCurve(QEasingCurve.Type.OutCubic)
        a.start()

    def _scan(self):
        self.scan_btn.setEnabled(False)
        self.pbar.setVisible(True)
        self.pbar.setRange(0, 0)
        self.vt_queue = []
        for t in [self.proc_tree, self.reg_tree, self.sch_tree, self.usb_tree, self.rec_tree, self.nf_tree]:
            t.clear()
        self.st = ScanThread()
        self.st.prog.connect(lambda m: self.status_bar.showMessage(m))
        self.st.res.connect(self._add)
        self.st.fin.connect(self._done)
        self.st.start()

    def _add(self, cat, items):
        trees = {"proc": self.proc_tree, "reg": self.reg_tree, "sch": self.sch_tree,
                 "usb": self.usb_tree, "rec": self.rec_tree, "new": self.nf_tree}
        t = trees.get(cat)
        if not t:
            return

        for item in items:
            ep = item.get("exe_path", "")
            url = vt_url(ep) if ep else ""
            vt_display = url if url else "—"

            if cat == "proc":
                qi = QTreeWidgetItem(t, [
                    str(item["pid"]), item["name"], item["path"],
                    item["signer"], item["signed"], vt_display
                ])
                if url:
                    qi.setForeground(5, QColor("#0078D4"))
                    qi.setToolTip(5, f"VirusTotal\n{url}")
                if item["signed"] == "No":
                    for c in range(6):
                        qi.setForeground(c, QColor("#CC0000"))
                elif item["signed"] == "Bad":
                    for c in range(6):
                        qi.setForeground(c, QColor("#E07000"))
                if ep and self.act_vt.isChecked():
                    self.vt_queue.append((str(id(qi)), ep))

            elif cat in ("reg", "sch"):
                qi = QTreeWidgetItem(t, [
                    item["source"], item["name"], item["command"],
                    item["risk"], vt_display
                ])
                if url:
                    qi.setForeground(4, QColor("#0078D4"))
                    qi.setToolTip(4, f"VirusTotal\n{url}")
                if item["risk"] == "High":
                    for c in range(5):
                        qi.setForeground(c, QColor("#CC0000"))
                elif item["risk"] == "Medium":
                    for c in range(5):
                        qi.setForeground(c, QColor("#E07000"))
                if ep and self.act_vt.isChecked():
                    self.vt_queue.append((str(id(qi)), ep))

            elif cat == "usb":
                QTreeWidgetItem(t, [item["name"], item["last"], item["first"]])

            elif cat == "rec":
                QTreeWidgetItem(t, [item["name"], item["target"], item["date"]])

            elif cat == "new":
                qi = QTreeWidgetItem(t, [item["name"], item["path"], item["date"], vt_display])
                if url:
                    qi.setForeground(3, QColor("#0078D4"))
                    qi.setToolTip(3, f"VirusTotal\n{url}")
                if ep and self.act_vt.isChecked():
                    self.vt_queue.append((str(id(qi)), ep))

        self._filter()

    def _done(self):
        self.scan_btn.setEnabled(True)
        self.pbar.setVisible(False)

        if self.vt_queue and self.act_vt.isChecked():
            self.status_bar.showMessage("Checking VirusTotal...")
            self.vt = VTCheckThread(self.vt_queue)
            self.vt.vt_ready.connect(self._upd_vt)
            self.vt.fin.connect(lambda: self.status_bar.showMessage("Ready"))
            self.vt.start()
        else:
            self.status_bar.showMessage("Ready")

    def _upd_vt(self, item_id, stats, url):
        for tree in [self.proc_tree, self.reg_tree, self.sch_tree, self.nf_tree]:
            for i in range(tree.topLevelItemCount()):
                item = tree.topLevelItem(i)
                if str(id(item)) == item_id:
                    col = 5 if tree in (self.proc_tree, self.reg_tree, self.sch_tree) else 3
                    item.setText(col, stats)
                    item.setToolTip(col, f"VirusTotal: {stats}\n{url}")
                    if "/" in stats:
                        try:
                            mal, _ = stats.split("/")
                            if int(mal) > 0:
                                item.setForeground(col, QColor("#CC0000"))
                            else:
                                item.setForeground(col, QColor("#008800"))
                        except:
                            pass
                    return


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = PCCheckApp()
    w.show()
    sys.exit(app.exec())
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
梨园托管台 · 真实 Bot 托管后端（Python 标准库，零依赖）

能力（全部真实执行，不是演示数据）：
- 管理员注册/登录（scrypt 密码哈希 + HttpOnly 会话 Cookie + 登录限流）
- 上传 .py 文件：静态安全扫描（带行号），高风险需显式确认才登记
- 真实进程托管：优先 systemd 瞬时服务（CPUQuota / MemoryMax / 崩溃自动重启），
  无 systemd 的环境（Codespaces 等）回退独立进程组 + 内存上限 + 后端看门狗自动重启
- 真实指标：从 /proc 与 systemctl 读取 CPU / 内存 / 运行时长 / 重启次数
- 真实日志：进程模式读日志文件，systemd 模式读 journal
- 操作审计：登录、上传、启停、删除全部入 SQLite 留痕

运行：python3 server.py   （默认 0.0.0.0:8080，环境变量 PORT 可改）
数据目录：环境变量 BOT_HOST_DATA，默认 ./data
"""
import hashlib
import hmac
import json
import os
import re
import resource
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, quote
import urllib.request
import urllib.error

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("BOT_HOST_DATA", BASE_DIR / "data")).resolve()
BOTS_DIR = DATA_DIR / "bots"
LOGS_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "hosting.db"
HOST = os.environ.get("BOT_HOST_BIND", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("BOT_HOST_PORT", "8080")))
MAX_UPLOAD = 10 * 1024 * 1024
SESSION_DAYS = 7
DEFAULT_ALLOWED_ORIGINS = {"https://sadlili99.github.io"}
ALLOWED_ORIGINS = DEFAULT_ALLOWED_ORIGINS | {
    o.strip() for o in os.environ.get("BOT_HOST_ALLOWED_ORIGINS", "").split(",") if o.strip()
}

for d in (BOTS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

DB_LOCK = threading.RLock()
STATE_LOCK = threading.RLock()
PROCS = {}          # bot_id -> subprocess.Popen（进程模式，本进程拉起的）
SAMPLES = {}        # bot_id -> (ts, cpu_ticks_or_ns)
INTENTIONAL_STOP = set()
RESTART_DUE = {}    # bot_id -> epoch（进程模式自动重启排期）
HOST_CPU = {"percent": 0.0, "prev": None}
LOGIN_ATTEMPTS = {}  # ip -> [epoch,...]


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with DB_LOCK, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires REAL NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bots(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            cpu_limit INTEGER NOT NULL DEFAULT 50,
            mem_limit INTEGER NOT NULL DEFAULT 512,
            auto_restart INTEGER NOT NULL DEFAULT 1,
            scan_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'stopped',
            manager TEXT,
            pid INTEGER,
            unit TEXT,
            started_at REAL,
            last_exit_code INTEGER,
            last_error TEXT,
            restart_count INTEGER NOT NULL DEFAULT 0,
            total_starts INTEGER NOT NULL DEFAULT 0,
            consec_failures INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS optimize_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT NOT NULL,
            bot_name TEXT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            error_snapshot TEXT,
            result TEXT,
            result_note TEXT,
            resolved_at TEXT
        );
        CREATE TABLE IF NOT EXISTS metric_samples(
            ts INTEGER NOT NULL,
            bot_id TEXT NOT NULL,
            cpu REAL NOT NULL,
            mem_mb REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_samples ON metric_samples(bot_id, ts);
        """)
        # 迁移：文件内容同时存一份到数据库 BLOB，磁盘文件丢失也能按库恢复，
        # 保证重新登录/后端重启后文件还在（数据一律保留，不清库）。
        cols = [r["name"] for r in c.execute("PRAGMA table_info(bots)").fetchall()]
        if "file_blob" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN file_blob BLOB")
        if "missing_module" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN missing_module TEXT")
        if "missing_package" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN missing_package TEXT")
        # 报错去重：记最后一次报错的签名、截取片段、重复次数与事件键，
        # 自动重启反复报同一个错时只记一次签名、次数累加，不全文刷屏。
        if "error_sig" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN error_sig TEXT")
        if "error_tail" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN error_tail TEXT")
        if "error_repeat" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN error_repeat INTEGER DEFAULT 0")
        if "error_event" not in cols:
            c.execute("ALTER TABLE bots ADD COLUMN error_event TEXT")
init_db()


def audit(actor, action, target=None, detail=None):
    try:
        with DB_LOCK, db() as c:
            c.execute("INSERT INTO audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",
                      (now_iso(), actor, action, target, detail))
    except Exception:
        pass


# ---------------- 密码与会话 ----------------

def hash_password(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + "$" + h.hex()


def verify_password(pw, stored):
    try:
        salt_hex, h_hex = stored.split("$")
        h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def make_session(user_id):
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    with DB_LOCK, db() as c:
        c.execute("INSERT INTO sessions(token_hash,user_id,expires,created_at) VALUES(?,?,?,?)",
                  (th, user_id, time.time() + SESSION_DAYS * 86400, now_iso()))
    return token


def user_by_token(token):
    if not token:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    with DB_LOCK, db() as c:
        row = c.execute(
            "SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires>?", (th, time.time())).fetchone()
    return dict(row) if row else None


def drop_session(token):
    if not token:
        return
    th = hashlib.sha256(token.encode()).hexdigest()
    with DB_LOCK, db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))


# ---------------- 安全扫描 ----------------

RISK_RULES = [
    ("high", re.compile(r"shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|Path\([^)]*\)\.unlink"), "删除文件/目录"),
    ("high", re.compile(r"os\.system|os\.popen|subprocess\.|pty\.spawn"), "执行系统命令"),
    ("high", re.compile(r"credentials\.json|\.env\b|id_rsa|AppSecret|api[_-]?key\s*=|password\s*=|passwd\s*="), "疑似读取/硬编码凭证"),
    ("mid", re.compile(r"requests\.(post|put)|urllib\.request|http\.client|socket\.socket"), "对外网络请求"),
    ("mid", re.compile(r"\beval\s*\(|\bexec\s*\("), "动态执行代码 eval/exec"),
    ("mid", re.compile(r"while\s+True\s*:\s*pass"), "空转死循环（CPU 跑满）"),
    ("mid", re.compile(r"open\([^)]*['\"][wa]\+?['\"]"), "写文件"),
]


def scan_code(code):
    findings = []
    for i, line in enumerate(code.splitlines(), 1):
        for sev, pat, label in RISK_RULES:
            if pat.search(line):
                findings.append({"severity": sev, "line": i, "label": label,
                                   "code": line.strip()[:160]})
    return findings


# ---------------- 主机指标（真实 /proc） ----------------

def host_metrics():
    m = {"cpuPercent": round(HOST_CPU["percent"], 1), "load": list(os.getloadavg())}
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            info[k] = int(v.strip().split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        m["memTotalMB"] = total // 1024
        m["memUsedMB"] = (total - avail) // 1024
        m["memPercent"] = round((total - avail) / total * 100, 1) if total else 0
    except Exception:
        m.update({"memTotalMB": 0, "memUsedMB": 0, "memPercent": 0})
    try:
        du = shutil.disk_usage(DATA_DIR)
        m["diskTotalGB"] = round(du.total / 1e9, 1)
        m["diskUsedGB"] = round(du.used / 1e9, 1)
        m["diskPercent"] = round(du.used / du.total * 100, 1) if du.total else 0
    except Exception:
        m.update({"diskTotalGB": 0, "diskUsedGB": 0, "diskPercent": 0})
    try:
        up = float(Path("/proc/uptime").read_text().split()[0])
        m["uptimeSeconds"] = int(up)
    except Exception:
        m["uptimeSeconds"] = 0
    m["systemd"] = systemd_available()
    m["python"] = sys.version.split()[0]
    m["time"] = now_iso()
    return m


def _host_cpu_loop():
    def read():
        parts = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        vals = [int(x) for x in parts]
        return sum(vals), vals[3] + (vals[4] if len(vals) > 4 else 0)
    prev = None
    while True:
        try:
            cur = read()
            if prev:
                dt = cur[0] - prev[0]
                di = cur[1] - prev[1]
                if dt > 0:
                    HOST_CPU["percent"] = max(0.0, min(100.0, (1 - di / dt) * 100))
            prev = cur
        except Exception:
            pass
        time.sleep(2)


# ---------------- 进程 / systemd 管理 ----------------

_systemd_cache = {"ok": False, "ts": 0}


def systemd_available():
    if os.environ.get("BOT_HOST_DISABLE_SYSTEMD") == "1":
        return False
    if time.time() - _systemd_cache["ts"] < 30:
        return _systemd_cache["ok"]
    ok = False
    try:
        r = subprocess.run(["systemctl", "is-system-running"],
                           capture_output=True, text=True, timeout=3)
        ok = r.stdout.strip() in ("running", "degraded")
    except Exception:
        ok = False
    _systemd_cache.update(ok=ok, ts=time.time())
    return ok


def bot_dir(bot_id):
    return BOTS_DIR / bot_id


def bot_script(row):
    return bot_dir(row["id"]) / row["stored_name"]


def log_path(bot_id):
    return LOGS_DIR / f"{bot_id}.log"


def get_bot(bot_id):
    with DB_LOCK, db() as c:
        row = c.execute("SELECT * FROM bots WHERE id=?", (bot_id,)).fetchone()
    return dict(row) if row else None


def update_bot(bot_id, **kw):
    if not kw:
        return
    kw["updated_at"] = now_iso()
    cols = ", ".join(f"{k}=?" for k in kw)
    with DB_LOCK, db() as c:
        c.execute(f"UPDATE bots SET {cols} WHERE id=?", (*kw.values(), bot_id))


def proc_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def proc_metrics(pid):
    """返回 (cpu_percent, rss_mb)；进程不在返回 (0,0)。CPU% 为单核口径，可 >100 表示多核。"""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        rparen = stat.rfind(")")
        fields = stat[rparen + 2:].split()
        utime = int(fields[11]); stime = int(fields[12])
        ticks = utime + stime
        rss_mb = 0
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                rss_mb = int(line.split()[1]) // 1024
                break
        return ticks, rss_mb
    except Exception:
        return None, 0


CLK_TCK = os.sysconf("SC_CLK_TCK")


def cpu_percent_for(bot_id, ticks_or_ns, is_ns=False):
    t = time.time()
    with STATE_LOCK:
        prev = SAMPLES.get(bot_id)
        SAMPLES[bot_id] = (t, ticks_or_ns)
    if not prev:
        return 0.0
    dt = t - prev[0]
    if dt <= 0:
        return 0.0
    delta = ticks_or_ns - prev[1]
    if is_ns:
        pct = delta / (dt * 1e9) * 100
    else:
        pct = (delta / CLK_TCK) / dt * 100
    return max(0.0, round(pct, 1))


def systemd_show(unit):
    props = ["ActiveState", "SubState", "MainPID", "MemoryCurrent", "CPUUsageNSec",
             "NRestarts", "ExecMainStatus"]
    try:
        r = subprocess.run(["systemctl", "show", unit, "--property=" + ",".join(props)],
                           capture_output=True, text=True, timeout=4)
        out = {}
        for line in r.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out
    except Exception:
        return {}


def start_bot(bot_id, actor):
    row = get_bot(bot_id)
    if not row:
        return False, "Bot 不存在"
    sync_bot_state(row)
    row = get_bot(bot_id)
    if row["status"] == "running":
        return True, "已经在运行"
    script = bot_script(row)
    if not script.exists():
        # 磁盘文件不在时从数据库 BLOB 恢复（文件双份存储：磁盘 + 数据库）
        restored = False
        try:
            with DB_LOCK, db() as c:
                brow = c.execute("SELECT file_blob FROM bots WHERE id=?", (bot_id,)).fetchone()
            if brow and brow["file_blob"]:
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_bytes(bytes(brow["file_blob"]))
                restored = True
        except Exception:
            restored = False
        if not restored:
            update_bot(bot_id, status="error", last_error="文件丢失且数据库无备份，无法启动")
            return False, "文件丢失且数据库无备份，无法启动"
    with STATE_LOCK:
        INTENTIONAL_STOP.discard(bot_id)
        RESTART_DUE.pop(bot_id, None)
    update_bot(bot_id, status="starting", last_error=None)
    started = False
    err = None
    if systemd_available():
        unit = row["unit"] or f"liyuan-bot-{bot_id}"
        subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=8)
        subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, timeout=8)
        cmd = ["systemd-run", f"--unit={unit}", "--collect",
               f"--description=Liyuan Bot {row['name']}",
               "-p", f"WorkingDirectory={bot_dir(bot_id)}",
               "-p", f"MemoryMax={row['mem_limit']}M",
               "-p", f"CPUQuota={row['cpu_limit']}%",
               "-p", "CPUAccounting=true",
               "-p", "MemoryAccounting=true",
               "-p", "Restart=on-failure" if row["auto_restart"] else "Restart=no",
               "-p", "RestartSec=2s",
               sys.executable, "-u", str(script)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if r.returncode == 0:
                started = True
                time.sleep(0.4)
                pid = None
                show = systemd_show(unit)
                if show.get("MainPID", "0").isdigit():
                    pid = int(show["MainPID"]) or None
                update_bot(bot_id, status="running", manager="systemd", unit=unit, pid=pid,
                           started_at=time.time(), total_starts=row["total_starts"] + 1)
            else:
                err = (r.stderr or r.stdout or "systemd-run 失败").strip()[:300]
        except Exception as e:
            err = str(e)[:300]
    if not started:
        # 回退：独立进程组 + 内存上限（RLIMIT_AS）+ 看门狗（监视线程负责自动重启）
        try:
            lf = open(log_path(bot_id), "ab")
            mem_bytes = int(row["mem_limit"]) * 1024 * 1024

            def _pre():
                os.setsid()
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                except Exception:
                    pass
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    pass

            env = dict(os.environ, PYTHONUNBUFFERED="1")
            p = subprocess.Popen([sys.executable, "-u", str(script)],
                                 cwd=str(bot_dir(bot_id)), stdin=subprocess.DEVNULL,
                                 stdout=lf, stderr=subprocess.STDOUT,
                                 preexec_fn=_pre, env=env)
            lf.close()
            with STATE_LOCK:
                PROCS[bot_id] = p
            update_bot(bot_id, status="running", manager="process", pid=p.pid, unit=None,
                       started_at=time.time(), total_starts=row["total_starts"] + 1,
                       last_error=("systemd 不可用，已用进程模式托管" if err else None))
            started = True
        except Exception as e:
            update_bot(bot_id, status="error", last_error=str(e)[:300])
            audit(actor, "start_failed", row["name"], str(e)[:200])
            return False, f"启动失败：{e}"
    audit(actor, "start", row["name"], f"manager={get_bot(bot_id)['manager']}")
    return True, "已启动"


def stop_bot(bot_id, actor, timeout=6):
    row = get_bot(bot_id)
    if not row:
        return False, "Bot 不存在"
    with STATE_LOCK:
        INTENTIONAL_STOP.add(bot_id)
        RESTART_DUE.pop(bot_id, None)
    if row["manager"] == "systemd" and row["unit"]:
        subprocess.run(["systemctl", "stop", row["unit"]], capture_output=True, timeout=timeout + 4)
    else:
        p = PROCS.get(bot_id)
        pid = row["pid"]
        if p and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
        elif proc_alive(pid):
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            t0 = time.time()
            while proc_alive(pid) and time.time() - t0 < timeout:
                time.sleep(0.2)
            if proc_alive(pid):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass
    with STATE_LOCK:
        PROCS.pop(bot_id, None)
        SAMPLES.pop(bot_id, None)
    update_bot(bot_id, status="stopped", pid=None, started_at=None)
    audit(actor, "stop", row["name"])
    return True, "已停止"


def sync_bot_state(row):
    """把数据库状态与真实进程状态对齐，顺带算指标。返回 (cpu%, rss_mb)。"""
    bot_id = row["id"]
    cpu_pct, rss = 0.0, 0
    if row["status"] in ("running", "starting"):
        if row["manager"] == "systemd" and row["unit"]:
            show = systemd_show(row["unit"])
            active = show.get("ActiveState", "")
            if active == "active":
                pid = int(show["MainPID"]) if show.get("MainPID", "0").isdigit() else None
                mem_cur = show.get("MemoryCurrent", "")
                rss = int(mem_cur) // (1024 * 1024) if mem_cur.isdigit() else 0
                if not rss and pid:
                    # 部分环境 cgroup 内存计数不可用，回退读主进程真实 RSS
                    _, rss = proc_metrics(pid)
                ns = show.get("CPUUsageNSec", "")
                if ns.isdigit():
                    cpu_pct = cpu_percent_for(bot_id, int(ns), is_ns=True)
                nr = show.get("NRestarts", "")
                kw = {}
                if pid and pid != row["pid"]:
                    kw["pid"] = pid
                if nr.isdigit() and int(nr) != row["restart_count"]:
                    kw["restart_count"] = int(nr)
                if kw:
                    update_bot(bot_id, **kw)
            elif active in ("failed",):
                code = show.get("ExecMainStatus", "")
                update_bot(bot_id, status="error", pid=None,
                           last_exit_code=int(code) if code.lstrip("-").isdigit() else None,
                           last_error="进程异常退出（systemd 已按策略处理）")
                record_error(bot_id, "s" + str(show.get("NRestarts", "")))
                with STATE_LOCK:
                    SAMPLES.pop(bot_id, None)
            elif active == "inactive":
                if bot_id not in INTENTIONAL_STOP:
                    update_bot(bot_id, status="stopped", pid=None,
                               last_error="进程已退出")
        else:
            p = PROCS.get(bot_id)
            if p is not None:
                rc = p.poll()
                if rc is None:
                    ticks, rss = proc_metrics(p.pid)
                    if ticks is not None:
                        cpu_pct = cpu_percent_for(bot_id, ticks)
                else:
                    with STATE_LOCK:
                        PROCS.pop(bot_id, None)
                        SAMPLES.pop(bot_id, None)
                    intentional = bot_id in INTENTIONAL_STOP
                    if intentional or rc == 0:
                        update_bot(bot_id, status="stopped", pid=None, last_exit_code=rc)
                    else:
                        fails = row["consec_failures"] + 1
                        if row["auto_restart"] and fails <= 5:
                            with STATE_LOCK:
                                RESTART_DUE[bot_id] = time.time() + 2
                            update_bot(bot_id, status="error", pid=None, last_exit_code=rc,
                                       consec_failures=fails,
                                       last_error=f"异常退出（码 {rc}），2 秒后自动重启（第 {fails}/5 次）")
                        else:
                            update_bot(bot_id, status="error", pid=None, last_exit_code=rc,
                                       consec_failures=fails,
                                       last_error=f"异常退出（码 {rc}），已停止自动重启")
                        record_error(bot_id, f"p{fails}")
                    audit("system", "exit", row["name"], f"exit_code={rc}")
            elif proc_alive(row["pid"]):
                ticks, rss = proc_metrics(row["pid"])
                if ticks is not None:
                    cpu_pct = cpu_percent_for(bot_id, ticks)
            elif row["status"] == "running":
                update_bot(bot_id, status="error", pid=None, last_error="进程已不存在（后端重启后未恢复）")
    row2 = get_bot(bot_id)
    # 一旦确认在运行，旧的报错记录与连续失败计数清零：下一次崩溃从 1 重新数。
    if row2 and row2["status"] == "running" and (
            row2["consec_failures"] or row2.get("error_sig")):
        update_bot(bot_id, consec_failures=0, error_sig=None, error_tail=None,
                   error_repeat=0, error_event=None)
        row2 = get_bot(bot_id)
    return row2, cpu_pct, rss


MODULE_PACKAGE_MAP = {
    "telebot": "pyTelegramBotAPI", "PIL": "Pillow", "cv2": "opencv-python",
    "yaml": "PyYAML", "bs4": "beautifulsoup4", "dotenv": "python-dotenv",
    "sklearn": "scikit-learn", "telegram": "python-telegram-bot",
    "discord": "discord.py", "flask": "Flask", "requests": "requests",
    "aiohttp": "aiohttp", "numpy": "numpy", "pandas": "pandas",
    "openai": "openai", "anthropic": "anthropic", "redis": "redis",
    "pymysql": "PyMySQL", "psycopg2": "psycopg2-binary", "sqlalchemy": "SQLAlchemy",
    "lxml": "lxml", "Crypto": "pycryptodome", "jwt": "PyJWT",
    "qrcode": "qrcode", "websocket": "websocket-client", "websockets": "websockets",
}
MISSING_RE = re.compile(r"(?:ModuleNotFoundError|ImportError): No module named '([A-Za-z0-9_\\.]+)'")


def detect_missing_lib(row):
    """从真实日志里识别缺库错误，返回 (module, package) 或 (None, None)。只识别、不安装。"""
    try:
        lines = read_logs(row, 80)
    except Exception:
        return None, None
    found = None
    for ln in lines:
        m = MISSING_RE.search(ln)
        if m:
            found = m.group(1)
    if not found:
        return None, None
    root = found.split(".")[0]
    return root, MODULE_PACKAGE_MAP.get(root, root)


ERR_LINE_RE = re.compile(r"([A-Za-z_][\w.]*?(?:Error|Exception|Interrupt|Exit|Failure))\s*:\s*(.*)")


def extract_error(lines):
    """从日志里截取报错：签名取最后一条异常行，片段取最后 12 行（不全文刷屏）。"""
    sig = None
    for ln in lines:
        m = ERR_LINE_RE.search(ln)
        if m:
            sig = (m.group(1) + ": " + m.group(2).strip())[:200]
    tail_lines = [ln for ln in lines if ln.strip()][-12:]
    tail = "\n".join(tail_lines)[-800:]
    return sig, tail


def record_error(bot_id, event_key):
    """一次新的崩溃事件：同签名则重复次数 +1，否则重置为 1；同一事件不重复计。"""
    row = get_bot(bot_id)
    if not row or row.get("error_event") == event_key:
        return
    try:
        lines = read_logs(row, 80)
    except Exception:
        lines = []
    sig, tail = extract_error(lines)
    if sig and sig == row.get("error_sig"):
        rep = (row.get("error_repeat") or 0) + 1
    else:
        rep = 1
    update_bot(bot_id, error_sig=sig, error_tail=tail, error_repeat=rep,
               error_event=event_key)


def serialize_bot(row):
    row, cpu_pct, rss = sync_bot_state(row)
    # 异常时自动识别缺库（只诊断展示，安装与否由点「AI 优化」后小梨审核处理）
    if row["status"] == "error":
        mod, pkg = detect_missing_lib(row)
        if mod != row.get("missing_module"):
            update_bot(row["id"], missing_module=mod, missing_package=pkg)
            row = get_bot(row["id"]) or row
    elif row.get("missing_module"):
        update_bot(row["id"], missing_module=None, missing_package=None)
        row = get_bot(row["id"]) or row
    up = None
    if row["status"] == "running" and row["started_at"]:
        up = int(time.time() - row["started_at"])
    return {
        "id": row["id"], "name": row["name"], "filename": row["filename"],
        "size": row["size"], "sha256": row["sha256"],
        "cpuLimit": row["cpu_limit"], "memLimit": row["mem_limit"],
        "autoRestart": bool(row["auto_restart"]),
        "scan": json.loads(row["scan_json"] or "[]"),
        "status": row["status"], "manager": row["manager"], "pid": row["pid"],
        "cpuPercent": cpu_pct, "memMB": rss,
        "uptimeSeconds": up,
        "lastExitCode": row["last_exit_code"], "lastError": row["last_error"],
        "errorSig": row.get("error_sig"), "errorTail": row.get("error_tail"),
        "errorRepeat": row.get("error_repeat") or 0,
        "missingModule": row.get("missing_module"), "missingPackage": row.get("missing_package"),
        "restartCount": row["restart_count"], "totalStarts": row["total_starts"],
        "createdAt": row["created_at"], "updatedAt": row["updated_at"],
    }


def read_logs(row, tail=200):
    tail = max(1, min(1000, tail))
    if row["manager"] == "systemd" and row["unit"]:
        try:
            r = subprocess.run(["journalctl", "-u", row["unit"], "--no-pager", "-o", "cat",
                                "--no-hostname", "-n", str(tail)],
                               capture_output=True, text=True, timeout=6)
            lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
            return lines[-tail:]
        except Exception as e:
            return [f"[读取 journal 失败：{e}]"]
    p = log_path(row["id"])
    if not p.exists():
        return []
    try:
        data = p.read_bytes()[-512 * 1024:]
        text = data.decode("utf-8", errors="replace")
        return text.splitlines()[-tail:]
    except Exception as e:
        return [f"[读取日志失败：{e}]"]


_LAST_SAMPLE = [0.0]
_LAST_AUTO_AUDIT = {}


def sample_metrics():
    """每 30 秒采样一次主机与每个运行中 Bot 的真实 CPU/内存，保留 48 小时，
    供总览与 Bot 详情的近 24 小时柱状图使用。"""
    now = int(time.time())
    samples = []
    h = host_metrics()
    samples.append((now, "", float(h["cpuPercent"]), float(h["memUsedMB"])))
    with DB_LOCK, db() as c:
        bots = [dict(r) for r in c.execute(
            "SELECT * FROM bots WHERE status='running'").fetchall()]
    for b in bots:
        try:
            _, cpu, rss = sync_bot_state(b)
            samples.append((now, b["id"], float(cpu), float(rss)))
        except Exception:
            pass
    with DB_LOCK, db() as c:
        c.executemany("INSERT INTO metric_samples(ts,bot_id,cpu,mem_mb) VALUES(?,?,?,?)",
                      samples)
        c.execute("DELETE FROM metric_samples WHERE ts < ?", (now - 48 * 3600,))


def monitor_loop():
    while True:
        try:
            with DB_LOCK, db() as c:
                rows = [dict(r) for r in c.execute(
                    "SELECT * FROM bots WHERE status IN ('running','starting','error')").fetchall()]
            for row in rows:
                try:
                    sync_bot_state(row)
                except Exception:
                    pass
            if time.time() - _LAST_SAMPLE[0] >= 30:
                _LAST_SAMPLE[0] = time.time()
                try:
                    sample_metrics()
                except Exception:
                    pass
            due = []
            with STATE_LOCK:
                for bid, ts in list(RESTART_DUE.items()):
                    if time.time() >= ts:
                        due.append(bid)
                        RESTART_DUE.pop(bid, None)
            for bid in due:
                r = get_bot(bid)
                if r and r["status"] == "error" and r["auto_restart"]:
                    start_bot(bid, "system")
                    rr = get_bot(bid)
                    if rr:
                        update_bot(bid, restart_count=rr["restart_count"] + 1)
                    # 同一个错反复自动重启时，审计只记一次（30 分钟内同签名不刷屏）
                    _sig = r.get("error_sig") or ""
                    _last = _LAST_AUTO_AUDIT.get(bid)
                    if not _last or _last[0] != _sig or time.time() - _last[1] > 1800:
                        _LAST_AUTO_AUDIT[bid] = (_sig, time.time())
                        audit("system", "auto_restart", r["name"])
        except Exception:
            pass
        time.sleep(2)


# ---------------- HTTP ----------------

def register_bot(u, name, base, raw, code, cpu, mem, auto_restart, confirm_risk, action):
    """登记一个 Bot（上传与 GitHub 导入共用）：扫描→写文件→入库→审计。
    返回 (http_status, payload)。"""
    findings = scan_code(code)
    high = [f for f in findings if f["severity"] == "high"]
    if high and not confirm_risk:
        return 422, {"error": "扫描发现高风险调用，需要确认后才能登记",
                     "findings": findings, "requiresConfirmation": True}
    bot_id = uuid.uuid4().hex[:12]
    d = bot_dir(bot_id)
    d.mkdir(parents=True, exist_ok=True)
    stored = "main.py"
    (d / stored).write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    with DB_LOCK, db() as c:
        c.execute(
            "INSERT INTO bots(id,name,filename,stored_name,size,sha256,cpu_limit,mem_limit,"
            "auto_restart,scan_json,status,file_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,"
            "?,?,?,?,'stopped',?,?,?)",
            (bot_id, name, base, stored, len(raw), sha, cpu, mem,
             1 if auto_restart else 0, json.dumps(findings, ensure_ascii=False),
             raw, now_iso(), now_iso()))
    audit(u["username"], action, name,
          f"{base} {len(raw)}B risks={len(findings)} confirmed={confirm_risk}")
    return 201, {"bot": serialize_bot(get_bot(bot_id))}


def resolve_github_url(url):
    """把 GitHub 文件页/raw 链接统一成 raw 下载地址；只允许 github 域名与 .py 文件。
    返回 (raw_url, filename, error)。"""
    try:
        p = urlparse(url)
    except Exception:
        return None, None, "链接格式不正确"
    if p.scheme != "https" or not p.hostname:
        return None, None, "只支持 https 链接"
    host = p.hostname.lower()
    parts = [unquote(x) for x in p.path.split("/") if x]
    if host == "raw.githubusercontent.com":
        if len(parts) < 4:
            return None, None, "链接不完整"
        base = parts[-1]
        if not base.lower().endswith(".py"):
            return None, None, "只接受 .py 文件"
        return url, base, None
    if host == "github.com":
        if len(parts) < 5 or parts[2] not in ("blob", "raw"):
            return None, None, "请粘贴 GitHub 文件页链接（…/blob/分支/路径.py）或 raw 链接"
        owner, repo, branch = parts[0], parts[1], parts[3]
        rest = "/".join(quote(x) for x in parts[4:])
        base = parts[-1]
        if not base.lower().endswith(".py"):
            return None, None, "只接受 .py 文件"
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}", base, None
    return None, None, "只支持 github.com / raw.githubusercontent.com 的链接"


class Handler(BaseHTTPRequestHandler):
    server_version = "LiyuanHost/2.0"
    protocol_version = "HTTP/1.1"

    # -- 基础工具 --
    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _cors_headers(self):
        origin = self.headers.get("Origin", "")
        if origin and (origin in ALLOWED_ORIGINS or origin == f"http://{self.headers.get('Host','')}"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def _origin_ok_for_write(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        if origin in (f"http://{host}", f"https://{host}"):
            return True
        return origin in ALLOWED_ORIGINS

    def send_json(self, code, obj, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def read_json(self, max_bytes=1024 * 1024):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > max_bytes:
            raise ValueError("请求体过大")
        raw = self.rfile.read(n) if n > 0 else b""
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def session_token(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("bot_host_session="):
                return part.split("=", 1)[1]
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def current_user(self):
        return user_by_token(self.session_token())

    def require_user(self):
        u = self.current_user()
        if not u:
            self.send_json(401, {"error": "未登录"})
            return None
        return u

    def client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    # -- 路由 --
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, X-Bot-Name, X-File-Name, X-CPU-Limit, X-Memory-Limit, "
                         "X-Auto-Restart, X-Confirm-Risk, X-Requested-With")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            if path in ("/", "/index.html"):
                return self.serve_index()
            if path == "/api/health":
                return self.send_json(200, {"ok": True, "service": "liyuan-bot-host",
                                             "version": "2.0", "time": now_iso(),
                                             "systemd": systemd_available()})
            if path == "/api/setup/status":
                with DB_LOCK, db() as c:
                    n = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
                return self.send_json(200, {"needsSetup": n == 0})
            if not path.startswith("/api/"):
                return self.send_json(404, {"error": "不存在"})
            u = self.require_user()
            if not u:
                return
            if path == "/api/me":
                return self.send_json(200, {"user": u})
            if path == "/api/host":
                return self.send_json(200, {"host": host_metrics()})
            if path == "/api/metrics":
                qs = parse_qs(parsed.query)
                bot = (qs.get("bot") or ["host"])[0]
                bid = "" if bot == "host" else bot
                if bid and not get_bot(bid):
                    return self.send_json(404, {"error": "Bot 不存在"})
                since = int(time.time()) - 24 * 3600
                with DB_LOCK, db() as c:
                    srows = c.execute(
                        "SELECT ts,cpu,mem_mb FROM metric_samples WHERE bot_id=? AND ts>=? "
                        "ORDER BY ts", (bid, since)).fetchall()
                buckets = {}
                for r in srows:
                    h0 = r["ts"] - r["ts"] % 3600
                    b = buckets.setdefault(h0, {"t": h0, "cpu": [], "mem": []})
                    b["cpu"].append(r["cpu"])
                    b["mem"].append(r["mem_mb"])
                out = [{"t": b["t"],
                        "cpuAvg": round(sum(b["cpu"]) / len(b["cpu"]), 1),
                        "cpuMax": round(max(b["cpu"]), 1),
                        "memAvg": round(sum(b["mem"]) / len(b["mem"]), 1),
                        "memMax": round(max(b["mem"]), 1),
                        "n": len(b["cpu"])}
                       for _, b in sorted(buckets.items())]
                return self.send_json(200, {"bot": bot, "buckets": out})
            if path == "/api/bots":
                with DB_LOCK, db() as c:
                    rows = [dict(r) for r in c.execute(
                        "SELECT * FROM bots ORDER BY created_at DESC").fetchall()]
                bots = [serialize_bot(r) for r in rows]
                summary = {
                    "total": len(bots),
                    "running": sum(1 for b in bots if b["status"] == "running"),
                    "stopped": sum(1 for b in bots if b["status"] == "stopped"),
                    "error": sum(1 for b in bots if b["status"] == "error"),
                    "restarts": sum(b["restartCount"] for b in bots),
                }
                return self.send_json(200, {"bots": bots, "summary": summary})
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/logs", path)
            if m:
                row = get_bot(m.group(1))
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                tail = int(qs.get("tail", ["200"])[0])
                return self.send_json(200, {"lines": read_logs(row, tail)})
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/download", path)
            if m:
                row = get_bot(m.group(1))
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                script = bot_script(row)
                data = None
                if script.exists():
                    data = script.read_bytes()
                else:
                    with DB_LOCK, db() as c:
                        brow = c.execute("SELECT file_blob FROM bots WHERE id=?",
                                         (row["id"],)).fetchone()
                    if brow and brow["file_blob"]:
                        data = bytes(brow["file_blob"])
                if data is None:
                    return self.send_json(404, {"error": "文件不存在"})
                audit(u["username"], "download", row["name"], row["filename"])
                self.send_response(200)
                self.send_header("Content-Type", "text/x-python; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                from urllib.parse import quote as _q
                self.send_header("Content-Disposition",
                                 f"attachment; filename*=UTF-8''{_q(row['filename'])}")
                self._cors_headers()
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)
                return
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/file", path)
            if m:
                row = get_bot(m.group(1))
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                script = bot_script(row)
                data = None
                if script.exists():
                    data = script.read_bytes()
                else:
                    with DB_LOCK, db() as c:
                        brow = c.execute("SELECT file_blob FROM bots WHERE id=?",
                                         (row["id"],)).fetchone()
                    if brow and brow["file_blob"]:
                        data = bytes(brow["file_blob"])
                if data is None:
                    return self.send_json(404, {"error": "文件不存在"})
                try:
                    content = data.decode("utf-8")
                except UnicodeDecodeError:
                    return self.send_json(400, {"error": "文件不是纯文本，无法在线编辑"})
                return self.send_json(200, {"content": content, "size": len(data),
                                            "filename": row["filename"]})
            if path == "/api/optimize-requests":
                with DB_LOCK, db() as c:
                    rows = [dict(r) for r in c.execute(
                        "SELECT * FROM optimize_requests ORDER BY id DESC LIMIT 50").fetchall()]
                return self.send_json(200, {"requests": rows})
            if path == "/api/audit":
                limit = max(1, min(300, int(qs.get("limit", ["100"])[0])))
                with DB_LOCK, db() as c:
                    rows = [dict(r) for r in c.execute(
                        "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
                return self.send_json(200, {"audit": rows})
            return self.send_json(404, {"error": "接口不存在"})
        except Exception as e:
            return self.send_json(500, {"error": f"服务器错误：{e}"})

    def serve_index(self):
        f = BASE_DIR / "index.html"
        if not f.exists():
            return self.send_json(404, {"error": "index.html 不存在"})
        body = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path.startswith("/api/") and not self._origin_ok_for_write():
                return self.send_json(403, {"error": "来源不被允许"})
            if path == "/api/setup":
                data = self.read_json()
                username = (data.get("username") or "").strip()
                password = data.get("password") or ""
                if len(username) < 3 or len(password) < 8:
                    return self.send_json(400, {"error": "用户名至少 3 位，密码至少 8 位"})
                with DB_LOCK, db() as c:
                    n = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
                    if n > 0:
                        return self.send_json(409, {"error": "管理员已创建，请直接登录"})
                    cur = c.execute("INSERT INTO users(username,pw_hash,created_at) VALUES(?,?,?)",
                                    (username, hash_password(password), now_iso()))
                    uid = cur.lastrowid
                token = make_session(uid)
                audit(username, "setup", username, "创建管理员")
                return self.send_json(201, {"user": {"id": uid, "username": username}},
                                      {"Set-Cookie": self._cookie(token)})
            if path == "/api/login":
                ip = self.client_ip()
                lst = [t for t in LOGIN_ATTEMPTS.get(ip, []) if time.time() - t < 60]
                if len(lst) >= 10:
                    return self.send_json(429, {"error": "登录尝试过于频繁，请 1 分钟后再试"})
                lst.append(time.time())
                LOGIN_ATTEMPTS[ip] = lst
                data = self.read_json()
                username = (data.get("username") or "").strip()
                password = data.get("password") or ""
                with DB_LOCK, db() as c:
                    row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if not row or not verify_password(password, row["pw_hash"]):
                    audit(username or "?", "login_failed", None, f"ip={ip}")
                    return self.send_json(401, {"error": "用户名或密码不正确"})
                token = make_session(row["id"])
                audit(username, "login", None, f"ip={ip}")
                return self.send_json(200, {"user": {"id": row["id"], "username": username}},
                                      {"Set-Cookie": self._cookie(token)})
            # 以下都要登录
            u = self.require_user()
            if not u:
                return
            if path == "/api/logout":
                drop_session(self.session_token())
                audit(u["username"], "logout")
                return self.send_json(200, {"ok": True},
                                      {"Set-Cookie": "bot_host_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
            if path == "/api/bots":
                return self.create_bot(u)
            if path == "/api/bots/import-github":
                return self.import_github(u)
            if path == "/api/bots/create-code":
                return self.create_code(u)
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/optimize-request", path)
            if m:
                bot_id = m.group(1)
                row = get_bot(bot_id)
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                snap = (row.get("error_sig") or row["last_error"] or "")[:300]
                if row.get("missing_module"):
                    snap = (snap + f" | 疑似缺库: {row['missing_module']} -> pip install "
                            f"{row.get('missing_package') or row['missing_module']}")[:300]
                with DB_LOCK, db() as c:
                    dup = c.execute(
                        "SELECT id FROM optimize_requests WHERE bot_id=? AND status='pending'",
                        (bot_id,)).fetchone()
                    if dup:
                        return self.send_json(200, {"ok": True, "message": "已有待处理的优化请求，不用重复点", "requestId": dup["id"]})
                    cur = c.execute(
                        "INSERT INTO optimize_requests(bot_id,bot_name,ts,actor,status,error_snapshot)"
                        " VALUES(?,?,?,?, 'pending', ?)",
                        (bot_id, row["name"], now_iso(), u["username"], snap))
                    rid = cur.lastrowid
                audit(u["username"], "optimize_request", row["name"],
                      f"request#{rid} status={row['status']} err={snap[:120]}")
                return self.send_json(201, {"ok": True, "requestId": rid,
                                             "message": "优化请求已提交，小梨会读取代码与日志后处理"})
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/file", path)
            if m:
                bot_id = m.group(1)
                row = get_bot(bot_id)
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                data = self.read_json()
                content = data.get("content")
                if not isinstance(content, str):
                    return self.send_json(400, {"error": "content 必须是文本"})
                raw = content.encode("utf-8")
                if b"\x00" in raw:
                    return self.send_json(400, {"error": "文件含 NUL 字节，拒绝保存"})
                if len(raw) > 10 * 1024 * 1024:
                    return self.send_json(400, {"error": "文件超过 10MB 上限"})
                findings = scan_code(content)
                high = [f for f in findings if f["severity"] == "high"]
                if high and not data.get("confirmRisk"):
                    return self.send_json(422, {"error": "新代码扫到高风险调用，确认后才能保存",
                                                "findings": findings})
                script = bot_script(row)
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_bytes(raw)
                update_bot(bot_id, file_blob=raw, size=len(raw),
                           sha256=hashlib.sha256(raw).hexdigest())
                audit(u["username"], "edit_file", row["name"],
                      f"{row['filename']} {len(raw)}B risks={len(findings)}")
                restarted = False
                if row["status"] == "running" and data.get("restart"):
                    try:
                        stop_bot(bot_id, u["username"])
                        start_bot(bot_id, u["username"])
                        restarted = True
                    except Exception as e:
                        return self.send_json(200, {"ok": True, "restarted": False,
                                                    "warn": f"已保存，但重启失败：{e}"})
                return self.send_json(200, {"ok": True, "restarted": restarted,
                                            "size": len(raw),
                                            "message": "已保存并重启" if restarted else "已保存"})
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/limits", path)
            if m:
                bot_id = m.group(1)
                row = get_bot(bot_id)
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                data = self.read_json()
                try:
                    cpu = int(data.get("cpuLimit"))
                    mem = int(data.get("memLimit"))
                except (TypeError, ValueError):
                    return self.send_json(400, {"error": "资源上限格式不正确"})
                cpu = max(5, min(400, cpu))
                mem = max(64, min(8192, mem))
                update_bot(bot_id, cpu_limit=cpu, mem_limit=mem)
                audit(u["username"], "edit_limits", row["name"],
                      f"cpu={cpu}% mem={mem}MB")
                restarted = False
                if row["status"] == "running" and data.get("restart"):
                    try:
                        stop_bot(bot_id, u["username"])
                        start_bot(bot_id, u["username"])
                        restarted = True
                    except Exception as e:
                        return self.send_json(200, {"ok": True, "restarted": False,
                                                    "warn": f"已保存，但重启失败：{e}"})
                return self.send_json(200, {"ok": True, "restarted": restarted,
                                            "cpuLimit": cpu, "memLimit": mem,
                                            "message": "已保存并重启，上限已生效" if restarted
                                            else "已保存，下次启动时生效"})
            m = re.fullmatch(r"/api/optimize-requests/(\d+)/resolve", path)
            if m:
                data = self.read_json()
                result = data.get("result")
                note = (data.get("note") or "")[:500]
                if result not in ("done", "declined"):
                    return self.send_json(400, {"error": "result 只能是 done 或 declined"})
                with DB_LOCK, db() as c:
                    r0 = c.execute("SELECT * FROM optimize_requests WHERE id=?",
                                   (int(m.group(1)),)).fetchone()
                    if not r0:
                        return self.send_json(404, {"error": "请求不存在"})
                    c.execute("UPDATE optimize_requests SET status='resolved', result=?, "
                              "result_note=?, resolved_at=? WHERE id=?",
                              (result, note, now_iso(), int(m.group(1))))
                audit(u["username"], "optimize_resolve", r0["bot_name"],
                      f"request#{m.group(1)} {result}: {note[:120]}")
                return self.send_json(200, {"ok": True})
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)/(start|stop|restart)", path)
            if m:
                bot_id, act = m.group(1), m.group(2)
                row = get_bot(bot_id)
                if not row:
                    return self.send_json(404, {"error": "Bot 不存在"})
                if act == "start":
                    ok, msg = start_bot(bot_id, u["username"])
                elif act == "stop":
                    ok, msg = stop_bot(bot_id, u["username"])
                else:
                    stop_bot(bot_id, u["username"])
                    ok, msg = start_bot(bot_id, u["username"])
                    msg = "已重启" if ok else msg
                    if ok:
                        audit(u["username"], "restart", row["name"])
                return self.send_json(200 if ok else 400,
                                      {"ok": ok, "message": msg, "bot": serialize_bot(get_bot(bot_id))})
            return self.send_json(404, {"error": "接口不存在"})
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        except Exception as e:
            return self.send_json(500, {"error": f"服务器错误：{e}"})

    def _cookie(self, token):
        return (f"bot_host_session={token}; Path=/; Max-Age={SESSION_DAYS*86400}; "
                f"HttpOnly; SameSite=Lax")

    def create_bot(self, u):
        name = unquote(self.headers.get("X-Bot-Name", "")).strip()
        filename = unquote(self.headers.get("X-File-Name", "")).strip()
        try:
            cpu = int(self.headers.get("X-CPU-Limit", "50"))
            mem = int(self.headers.get("X-Memory-Limit", "512"))
        except ValueError:
            return self.send_json(400, {"error": "资源上限格式不正确"})
        cpu = max(5, min(400, cpu))
        mem = max(64, min(8192, mem))
        auto_restart = self.headers.get("X-Auto-Restart", "1") == "1"
        confirm_risk = self.headers.get("X-Confirm-Risk", "0") == "1"
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0:
            return self.send_json(400, {"error": "文件为空"})
        if n > MAX_UPLOAD:
            return self.send_json(413, {"error": "文件超过 10 MB 上限"})
        raw = self.rfile.read(n)
        base = Path(filename).name
        if not base.lower().endswith(".py"):
            return self.send_json(400, {"error": "只接受 .py 文件"})
        if b"\x00" in raw:
            return self.send_json(400, {"error": "文件不是文本 Python 代码"})
        try:
            code = raw.decode("utf-8")
        except UnicodeDecodeError:
            return self.send_json(400, {"error": "文件不是 UTF-8 文本"})
        if not name:
            name = base[:-3].replace("_", " ").replace("-", " ").strip() or "未命名 Bot"
        status, payload = register_bot(u, name, base, raw, code, cpu, mem,
                                       auto_restart, confirm_risk, "upload")
        return self.send_json(status, payload)

    def import_github(self, u):
        data = self.read_json()
        url = (data.get("url") or "").strip()
        auto_restart = bool(data.get("autoRestart", True))
        confirm_risk = bool(data.get("confirmRisk"))
        raw_url, base, err = resolve_github_url(url)
        if err:
            return self.send_json(400, {"error": err})
        try:
            req = urllib.request.Request(raw_url, headers={"User-Agent": "liyuan-bot-host"})
            with urllib.request.urlopen(req, timeout=25) as r:
                raw = r.read(MAX_UPLOAD + 1)
        except Exception as e:
            return self.send_json(502, {"error": f"从 GitHub 拉取失败：{e}"})
        if not raw:
            return self.send_json(400, {"error": "文件为空"})
        if len(raw) > MAX_UPLOAD:
            return self.send_json(413, {"error": "文件超过 10 MB 上限"})
        if b"\x00" in raw:
            return self.send_json(400, {"error": "文件不是文本 Python 代码"})
        try:
            code = raw.decode("utf-8")
        except UnicodeDecodeError:
            return self.send_json(400, {"error": "文件不是 UTF-8 文本"})
        name = base[:-3].replace("_", " ").replace("-", " ").strip() or "未命名 Bot"
        status, payload = register_bot(u, name, base, raw, code, 50, 512,
                                       auto_restart, confirm_risk, "import")
        return self.send_json(status, payload)

    def create_code(self, u):
        """网页端在线写代码：手动写入 .py → 直接登记 → 马上启动。"""
        data = self.read_json()
        name = (data.get("name") or "").strip()
        base = Path((data.get("filename") or "bot.py").strip()).name
        if not base.lower().endswith(".py"):
            return self.send_json(400, {"error": "只接受 .py 文件"})
        content = data.get("content")
        if not isinstance(content, str) or not content.strip():
            return self.send_json(400, {"error": "代码不能为空"})
        raw = content.encode("utf-8")
        if b"\x00" in raw:
            return self.send_json(400, {"error": "代码含 NUL 字节"})
        if len(raw) > MAX_UPLOAD:
            return self.send_json(413, {"error": "代码超过 10 MB 上限"})
        try:
            cpu = int(data.get("cpuLimit", 50))
            mem = int(data.get("memLimit", 512))
        except (TypeError, ValueError):
            return self.send_json(400, {"error": "资源上限格式不正确"})
        cpu = max(5, min(400, cpu))
        mem = max(64, min(8192, mem))
        auto_restart = bool(data.get("autoRestart", True))
        confirm_risk = bool(data.get("confirmRisk"))
        if not name:
            name = base[:-3].replace("_", " ").replace("-", " ").strip() or "未命名 Bot"
        status, payload = register_bot(u, name, base, raw, content, cpu, mem,
                                       auto_restart, confirm_risk, "create_code")
        if status != 201:
            return self.send_json(status, payload)
        bot_id = payload["bot"]["id"]
        ok, msg = start_bot(bot_id, u["username"])
        payload = dict(payload)
        payload["started"] = ok
        payload["startMessage"] = msg
        if ok:
            audit(u["username"], "start", name, "在线编写创建后自动启动")
        return self.send_json(201, payload)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path.startswith("/api/") and not self._origin_ok_for_write():
                return self.send_json(403, {"error": "来源不被允许"})
            u = self.require_user()
            if not u:
                return
            m = re.fullmatch(r"/api/bots/([0-9a-f]+)", path)
            if not m:
                return self.send_json(404, {"error": "接口不存在"})
            bot_id = m.group(1)
            row = get_bot(bot_id)
            if not row:
                return self.send_json(404, {"error": "Bot 不存在"})
            if row["status"] == "running":
                stop_bot(bot_id, u["username"])
            shutil.rmtree(bot_dir(bot_id), ignore_errors=True)
            try:
                log_path(bot_id).unlink(missing_ok=True)
            except Exception:
                pass
            with DB_LOCK, db() as c:
                c.execute("DELETE FROM bots WHERE id=?", (bot_id,))
            audit(u["username"], "delete", row["name"], row["filename"])
            return self.send_json(200, {"ok": True})
        except Exception as e:
            return self.send_json(500, {"error": f"服务器错误：{e}"})

    do_HEAD = do_GET


def main():
    threading.Thread(target=_host_cpu_loop, daemon=True).start()
    threading.Thread(target=monitor_loop, daemon=True).start()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"梨园托管台后端已启动 http://{HOST}:{PORT} 数据目录 {DATA_DIR} "
          f"systemd={'可用' if systemd_available() else '不可用（进程模式）'}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

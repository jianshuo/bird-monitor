#!/usr/bin/env python3
"""BiRD Monitor — iCloud Drive 守护进程 bird 的只读状态监控器。

安全原则（硬约束）：
  * 从不打开 client.db / server.db（不 sqlite、不 cp、不 read），只对它们 stat()。
  * 数据库内容一律通过 `brctl dump` 由正在运行的 bird 自己读出来交给我们；
    绝不使用 `dump -d <db>`（直接读库文件）和 `dump -u`（会升级数据库）。
  * 只调用只读命令：brctl status/quota/accounts/dump、/usr/bin/log、ps、nettop、lsof，
    以及 libproc 的 proc_pid_rusage（读进程计数器）。
  * 所有 brctl 调用串行执行（一把锁），完整 dump 低频，避免给 bird 增加负担。
  * HTTP 只监听 127.0.0.1。
"""
import collections
import ctypes
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
DB_DIR = os.path.join(HOME, "Library/Application Support/CloudDocs/session/db")
SESSION_DIR = os.path.dirname(DB_DIR)
PORT = int(os.environ.get("BIRD_MONITOR_PORT", "8790"))


def _host():
    try:
        out = subprocess.run(["scutil", "--get", "ComputerName"], capture_output=True, timeout=5).stdout.decode().strip()
        if out:
            return out
    except Exception:  # noqa
        pass
    import socket
    return socket.gethostname().split(".")[0]


HOST = _host()
OS_VERSION = subprocess.run(["sw_vers", "-productVersion"], capture_output=True).stdout.decode().strip()

INTERVAL = {
    "proc": 2, "net": 5, "files": 5, "lsof": 15, "status": 60,
    "summary": 60, "quota": 1800, "full": 3600, "uploadfail": 600,
}
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TRACKED = ["bird", "cloudd", "nsurlsessiond", "fileproviderd"]

# 所有实际执行过的命令都记录下来，前端「安全说明」里原样展示
COMMANDS_USED = collections.OrderedDict()
BRCTL_LOCK = threading.Lock()
# 本监控器触发的、会让 bird 发起网络请求的调用时间窗（brctl quota 会触发 CKFetchUserQuotaOperation）
OWN_WINDOWS = collections.deque(maxlen=50)


def run(cmd, timeout=60, lock=False):
    key = " ".join(cmd)
    COMMANDS_USED[key] = COMMANDS_USED.get(key, 0) + 1
    t0 = time.time()
    try:
        if lock:
            with BRCTL_LOCK:
                p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        else:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = p.stdout.decode("utf-8", "replace")
        return ANSI.sub("", out), time.time() - t0, p.returncode
    except Exception as e:  # noqa
        return "", time.time() - t0, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------- state store
class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"started": time.time(), "errors": {}}
        self.hist = collections.defaultdict(lambda: collections.deque(maxlen=900))
        self.items_version = 0
        self.items = None
        self.raw = {}

    def set(self, key, value):
        with self.lock:
            self.data[key] = value
            self.data.setdefault("updated", {})[key] = time.time()

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def push(self, series, point):
        with self.lock:
            self.hist[series].append(point)

    def err(self, key, msg):
        with self.lock:
            if msg:
                self.data["errors"][key] = {"t": time.time(), "msg": msg}
            else:
                self.data["errors"].pop(key, None)


S = Store()
REFRESH = {k: threading.Event() for k in ("summary", "full", "status", "quota")}


# ---------------------------------------------------------------- libproc
class RUsage(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (n, ctypes.c_uint64) for n in (
            "user_time system_time pkg_idle_wkups interrupt_wkups pageins wired_size "
            "resident_size phys_footprint proc_start_abstime proc_exit_abstime "
            "child_user_time child_system_time child_pkg_idle_wkups child_interrupt_wkups "
            "child_pageins child_elapsed_abstime diskio_bytesread diskio_byteswritten").split()]


class Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


try:
    _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    _libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    _tb = Timebase()
    _libc.mach_timebase_info(ctypes.byref(_tb))
    TB = _tb.numer / _tb.denom
except Exception:  # noqa
    _libproc, TB = None, 1.0


def rusage(pid):
    if not _libproc:
        return None
    r = RUsage()
    if _libproc.proc_pid_rusage(int(pid), 2, ctypes.byref(r)) != 0:
        return None
    return {
        "cpu_ns": (r.user_time + r.system_time) * TB,
        "footprint": r.phys_footprint, "resident": r.resident_size,
        "read": r.diskio_bytesread, "write": r.diskio_byteswritten,
        "wakeups": r.pkg_idle_wkups + r.interrupt_wkups, "pageins": r.pageins,
    }


# ---------------------------------------------------------------- process sampler
def find_procs():
    out, _, _ = run(["ps", "-axo", "pid=,uid=,etime=,state=,comm="])
    uid = os.getuid()
    found = collections.defaultdict(list)
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid, puid, etime, state, comm = parts
        name = os.path.basename(comm)
        if name in TRACKED and int(puid) == uid and "CoreSimulator" not in comm:
            found[name].append({"pid": int(pid), "etime": etime, "state": state, "path": comm})
    return found


def threads_of(pid):
    out, _, _ = run(["ps", "-M", "-p", str(pid)])
    return max(0, len(out.strip().splitlines()) - 1)


def etime_secs(s):
    d = 0
    if "-" in s:
        d, s = s.split("-", 1)
    parts = [int(x) for x in s.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0)
    return int(d) * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]


def proc_loop():
    prev = {}
    tick = 0
    while True:
        try:
            now = time.time()
            procs = find_procs()
            snap = {}
            for name in TRACKED:
                inst = procs.get(name, [])
                agg = {"name": name, "running": bool(inst), "pids": [i["pid"] for i in inst],
                       "cpu": 0.0, "footprint": 0, "read_rate": 0.0, "write_rate": 0.0,
                       "read": 0, "write": 0, "wakeups_rate": 0.0}
                for i in inst:
                    ru = rusage(i["pid"])
                    if not ru:
                        continue
                    agg["footprint"] += ru["footprint"]
                    agg["read"] += ru["read"]
                    agg["write"] += ru["write"]
                    p = prev.get(i["pid"])
                    if p:
                        dt = now - p["t"]
                        agg["cpu"] += max(0, ru["cpu_ns"] - p["cpu_ns"]) / (dt * 1e9) * 100
                        agg["read_rate"] += max(0, ru["read"] - p["read"]) / dt
                        agg["write_rate"] += max(0, ru["write"] - p["write"]) / dt
                        agg["wakeups_rate"] += max(0, ru["wakeups"] - p["wakeups"]) / dt
                    prev[i["pid"]] = dict(ru, t=now)
                snap[name] = agg
                S.push(f"cpu.{name}", [now, round(agg["cpu"], 2)])
                S.push(f"mem.{name}", [now, agg["footprint"]])
            b = procs.get("bird", [])
            bird = snap["bird"]
            if b:
                main = b[0]
                bird.update(pid=main["pid"], etime=main["etime"], state=main["state"],
                            uptime=etime_secs(main["etime"]), path=main["path"])
                if tick % 5 == 0:
                    bird["threads"] = threads_of(main["pid"])
                    S.set("bird_threads", bird["threads"])
                else:
                    bird["threads"] = S.get("bird_threads")
                ru = rusage(main["pid"])
                if ru:
                    bird["cpu_total_s"] = ru["cpu_ns"] / 1e9
                    bird["pageins"] = ru["pageins"]
                S.push("io.read", [now, round(bird["read_rate"])])
                S.push("io.write", [now, round(bird["write_rate"])])
            S.set("procs", snap)
            S.err("proc", None)
        except Exception:  # noqa
            S.err("proc", traceback.format_exc(limit=2))
        tick += 1
        time.sleep(INTERVAL["proc"])


def net_loop():
    prev = {}
    while True:
        try:
            out, _, _ = run(["nettop", "-P", "-L", "1", "-n", "-x", "-J", "bytes_in,bytes_out"], timeout=20)
            procs = S.get("procs") or {}
            pid2name = {pid: n for n, p in procs.items() for pid in p.get("pids", [])}
            now = time.time()
            rate = {n: [0.0, 0.0] for n in TRACKED}
            for line in out.splitlines()[1:]:
                f = line.split(",")
                if len(f) < 3 or "." not in f[0]:
                    continue
                pname, _, pid = f[0].rpartition(".")
                try:
                    pid, bi, bo = int(pid), int(f[1] or 0), int(f[2] or 0)
                except ValueError:
                    continue
                name = pid2name.get(pid)
                if not name:
                    continue
                p = prev.get(pid)
                if p:
                    dt = now - p[0]
                    rate[name][0] += max(0, bi - p[1]) / dt
                    rate[name][1] += max(0, bo - p[2]) / dt
                prev[pid] = (now, bi, bo)
            tin = sum(v[0] for v in rate.values())
            tout = sum(v[1] for v in rate.values())
            S.push("net.in", [now, round(tin)])
            S.push("net.out", [now, round(tout)])
            S.set("net", {n: {"in": round(v[0]), "out": round(v[1])} for n, v in rate.items()})
            S.err("net", None)
        except Exception:  # noqa
            S.err("net", traceback.format_exc(limit=2))
        time.sleep(INTERVAL["net"])


# ---------------------------------------------------------------- db file metadata (stat only)
def files_loop():
    while True:
        try:
            now = time.time()
            files = []
            for fn in sorted(os.listdir(DB_DIR)):
                st = os.stat(os.path.join(DB_DIR, fn))
                files.append({"name": fn, "size": st.st_size, "mtime": st.st_mtime})
            sess = []
            for fn in sorted(os.listdir(SESSION_DIR)):
                st = os.stat(os.path.join(SESSION_DIR, fn))
                sess.append({"name": fn, "dir": os.path.isdir(os.path.join(SESSION_DIR, fn)),
                             "size": st.st_size, "mtime": st.st_mtime})
            by = {f["name"]: f["size"] for f in files}
            S.push("wal.client", [now, by.get("client.db-wal", 0)])
            S.push("wal.server", [now, by.get("server.db-wal", 0)])
            S.set("dbfiles", {"dir": DB_DIR, "files": files, "session": sess})
            S.err("files", None)
        except Exception:  # noqa
            S.err("files", traceback.format_exc(limit=2))
        time.sleep(INTERVAL["files"])


def lsof_loop():
    while True:
        try:
            procs = S.get("procs") or {}
            pid = (procs.get("bird") or {}).get("pid")
            if pid:
                out, _, _ = run(["lsof", "-n", "-P", "-p", str(pid), "-F", "ftn"], timeout=30)
                kinds = collections.Counter()
                files, cur = [], {}
                for line in out.splitlines():
                    if not line:
                        continue
                    k, v = line[0], line[1:]
                    if k == "f":
                        cur = {"fd": v}
                    elif k == "t":
                        cur["type"] = v
                        kinds[v] += 1
                    elif k == "n":
                        cur["name"] = v
                        if cur.get("type") == "REG" and not v.startswith(("/System/", "/usr/", "/Library/Apple/", "/private/var/db/")) \
                                and cur.get("fd", "").rstrip("urw").isdigit():
                            files.append(dict(cur))
                S.set("lsof", {"kinds": dict(kinds.most_common()), "files": files,
                               "total": sum(kinds.values())})
            S.err("lsof", None)
        except Exception:  # noqa
            S.err("lsof", traceback.format_exc(limit=2))
        time.sleep(INTERVAL["lsof"])


# ---------------------------------------------------------------- brctl: status / quota / accounts
def status_loop():
    while True:
        out, dt, rc = run(["brctl", "status"], timeout=60, lock=True)
        S.raw["status"] = out
        containers = []
        for line in out.splitlines():
            m = re.match(r"<(.+?)\[(\d+)\]\s+(\w+)\s+\{(.*)\}>\s*$", line.strip())
            if m:
                containers.append({"name": m.group(1), "id": m.group(2), "state": m.group(3),
                                   "detail": parse_brace_state(m.group(4))})
        pending = [l for l in out.splitlines() if l.strip() and not l.startswith("<") and "containers matching" not in l]
        S.set("status", {"containers": containers, "pending_lines": pending[:200],
                         "took": round(dt, 2), "rc": rc})
        REFRESH["status"].wait(INTERVAL["status"])
        REFRESH["status"].clear()


def quota_loop():
    while True:
        t0 = time.time()
        OWN_WINDOWS.append((t0 - 2, t0 + 70))   # 先登记（日志可能先于命令返回到达）
        q, _, _ = run(["brctl", "quota"], timeout=60, lock=True)
        OWN_WINDOWS[-1] = (t0 - 2, time.time() + 5)
        m = re.search(r"(\d+) bytes of quota remaining", q)
        a, _, _ = run(["brctl", "accounts"], timeout=60, lock=True)
        S.set("quota", {"remaining": int(m.group(1)) if m else None, "raw": q.strip(),
                        "accounts": a.strip()})
        REFRESH["quota"].wait(INTERVAL["quota"])
        REFRESH["quota"].clear()


def parse_brace_state(s):
    """把 'client:idle server:full-sync|x sync:has-synced-down last-sync:2026-.. , requestID:1' 拆成 dict。"""
    d = {}
    for m in re.finditer(r"([A-Za-z-]+):(\S+?)(?=,|\s|$)", s):
        d.setdefault(m.group(1), m.group(2).rstrip("}"))
    m = re.search(r"last-sync:([\d-]+ [\d:.]+)", s)
    if m:
        d["last-sync"] = m.group(1)
    if "caught-up" in s:
        d["caught-up"] = True
    d["raw"] = s
    return d


# ---------------------------------------------------------------- brctl dump -i (summary)
def section(text, name, nxt=None):
    m = re.search(r"^" + re.escape(name) + r"\s*\n-{10,}\n(.*?)(?=^\S[^\n]*\n-{10,}\n|\Z)", text, re.M | re.S)
    return m.group(1) if m else ""


def braced(s, key):
    """取 key{...} 里的内容，支持脱敏名里嵌套的 {n}。"""
    i = s.find(key + "{")
    if i < 0:
        return None
    i += len(key) + 1
    depth, j = 1, i
    while j < len(s) and depth:
        depth += {"{": 1, "}": -1}.get(s[j], 0)
        j += 1
    return s[i:j - 1]


def parse_kv_plus(block):
    d, last = collections.OrderedDict(), None
    for line in block.splitlines():
        m = re.match(r"\s*\+\s*([^:]+?):\s*(.*)$", line)
        if m:
            last = m.group(1).strip()
            d[last] = m.group(2).strip()
        elif last and line.strip():
            d[last] += " · " + line.strip()
    return d


def parse_budget(s):
    m = re.search(r"m:([\d.]+)%\s*\(([\d.]+)\)\s+h:([\d.]+)%\s*\(([\d.]+)\)\s+d:([\d.]+)%\s*\(([\d.]+)\)", s or "")
    if not m:
        return None
    v = [float(x) for x in m.groups()]
    return {"m": {"used": v[0], "cap": v[1]}, "h": {"used": v[2], "cap": v[3]}, "d": {"used": v[4], "cap": v[5]}}


def parse_summary(text):
    r = {}
    for key, pat in [("taken", r"dump taken at (\S+ \S+)"), ("account", r"\[account=(\d+)\]"),
                     ("db_version", r"database version: (\d+)"), ("db_id", r"database ID: (\S+)"),
                     ("fs_type", r"fsType: (\S+)"), ("startup_ago", r"startup ([\d.]+)s ago"),
                     ("source", r"from:\s+(.+)")]:
        m = re.search(pat, text)
        r[key] = m.group(1).strip() if m else None
    if r["startup_ago"]:
        r["startup_ago"] = float(r["startup_ago"])

    bh = section(text, re.search(r"^(boot_history.*)$", text, re.M).group(1)) if re.search(r"^boot_history", text, re.M) else ""
    boot, cur = {}, None
    for line in bh.splitlines():
        if re.match(r"^\S", line):
            cur = line.strip()
            boot[cur] = []
        elif cur and line.strip():
            boot[cur].append(line.strip())
    r["boot_history"] = boot

    r["server_state"] = parse_brace_state(section(text, "server_state").strip())
    cs = section(text, "client_state")
    r["client_state"] = {m.group(1).strip('"'): redact_raw(m.group(2).strip().strip('"'))
                         for m in re.finditer(r'^\s+("?[\w-]+"?) = (.*?);\s*$', cs, re.M)}
    devs = re.findall(r'^\s+o "(.*?)" \((\d+)\)', cs, re.M)
    r["devices"] = [{"name": n, "id": int(i)} for n, i in devs]

    r["system"] = parse_kv_plus(section(text, "system"))
    sched = section(text, "scheduler")
    r["scheduler"] = parse_kv_plus(sched)
    r["sync_budget"] = parse_budget(r["scheduler"].get("global sync up budget"))
    m = re.search(r"client:\s*[\w ]*?\((\d+)\),\s*server:\s*[\w ]*?\((\d+)\)", r["scheduler"].get("items", ""))
    r["item_counts"] = {"client": int(m.group(1)), "server": int(m.group(2))} if m else None
    m = re.search(r"\((\d+)\)", r["scheduler"].get("available quota", ""))
    r["available_quota"] = int(m.group(1)) if m else None

    m = re.search(r"^- <(.+?)\[(\d+)\]\s+(\w+)\s+\{(.*)\}>\s*$", text, re.M)
    r["zone"] = {"name": m.group(1), "id": m.group(2), "state": m.group(3),
                 "detail": parse_brace_state(m.group(4))} if m else None

    libs = []
    # macOS 26 每个资料库后面跟 “+ foreground clients:” 子块；macOS 15 没有，所以子块可选
    for m in re.finditer(r"\+ app library: <(.+?)\[(\d+)\]\s+(\w+)\s+\{s:([^}]*)\}(.*?)>[ \t]*\n(?:\s+\+ (\w+) clients:\n((?:\s{12}.*\n)*))?", text):
        rest = m.group(5)
        apps = braced(rest, "apps:")
        bundles = braced(rest, "bundles:")
        etag = re.search(r"etag:(\S+)", rest)
        meta = re.search(r"metadata:(\S+)", rest)
        flags = re.search(r"\}\s+((?:[A-Z]\w+\|?)+)\s+(?:bundles|salt)", rest)
        libs.append({
            "name": m.group(1), "id": int(m.group(2)), "state": m.group(3),
            "flags": [f for f in m.group(4).split("|") if f],
            "apps": [a.strip() for a in apps.split(";") if a.strip()] if apps else [],
            "bundles": [b.strip() for b in bundles.split(",") if b.strip()] if bundles else [],
            "etag": etag.group(1) if etag else None, "metadata": meta.group(1) if meta else None,
            "zone_flags": flags.group(1).split("|") if flags else [],
            "clients": [c.strip().rstrip("]") for c in (m.group(7) or "").splitlines() if c.strip()],
        })
    r["app_libraries"] = libs

    pa = re.search(r"pending activity\s*\n\s*=+\n(.*?)(?=\n\s*\n\s*server items|\n\s*server items)", text, re.S)
    pend = collections.OrderedDict()
    if pa:
        last = None
        for line in pa.group(1).splitlines():
            m = re.match(r"\s*\+?\s*([\w-]+):\s*(.*)$", line)
            if m:
                last = m.group(1)
                pend[last] = m.group(2).strip()
            elif last and line.strip():
                pend[last] += " · " + line.strip()
    r["pending"] = pend
    m = re.search(r"sync-up-scheduled:(\d+)", pend.get("up", ""))
    r["sync_up_scheduled"] = int(m.group(1)) if m else 0
    r["up_budget"] = parse_budget(pend.get("up-budget"))

    m = re.search(r"^(\d+) xpc clients:\n((?: o .*\n)*)", text, re.M)
    r["xpc_clients"] = [l.strip()[2:].rstrip("]") for l in m.group(2).splitlines()] if m else []
    m = re.search(r"^(\d+) misc operations:", text, re.M)
    r["misc_operations"] = int(m.group(1)) if m else None

    m = re.search(r"SyncHealthReport:\n((?:\w+: .*\n)*)", text)
    r["health_report"] = dict(l.split(": ", 1) for l in m.group(1).splitlines()) if m else {}
    m = re.search(r"Aggregated Telemetry:\n(.*?)\n\n", text, re.S)
    r["telemetry"] = m.group(1).strip() if m else None
    m = re.search(r"global progress \{(.*?)\}", text)
    r["global_progress"] = m.group(1) if m else None
    m = re.search(r"^\s+upload \{(.*?)\}", text, re.M)
    r["upload_progress"] = m.group(1) if m else None
    for key, title in [("throttles", "Named Throttle History"), ("pending_telemetry", "Pending Aggregated Telemetry")]:
        r[key] = section(text, title).strip()
    m = re.search(r"Special Sync Contexts\n-+\n(.*)", text, re.S)
    r["special_contexts"] = [l.strip("+ ").strip() for l in m.group(1).splitlines() if l.strip().startswith("+")] if m else []
    return r


def redact_raw(text):
    text = re.sub(r"(push token:\s+)\{.*?\}", r"\1{已隐藏}", text)
    text = re.sub(r"(token:unkown-token-size:\d+ \()[^)]*\)", r"\1已隐藏)", text)
    text = re.sub(r"data=[A-Za-z0-9+/=]{12,}", "data=已隐藏", text)
    text = re.sub(r"recordName=_[0-9a-f]{8,}", "recordName=已隐藏", text)
    return text


def summary_loop():
    time.sleep(1)
    while True:
        out, dt, rc = run(["brctl", "dump", "-i"], timeout=120, lock=True)
        if out:
            try:
                s = parse_summary(out)
                s["took"] = round(dt, 2)
                s["scheduler"].pop("push token", None)
                S.set("summary", s)
                S.raw["summary"] = redact_raw(out)
                S.push("pending.up", [time.time(), s["sync_up_scheduled"]])
                S.err("summary", None)
            except Exception:  # noqa
                S.err("summary", traceback.format_exc(limit=3))
        else:
            S.err("summary", f"brctl dump -i 失败 rc={rc}")
        REFRESH["summary"].wait(INTERVAL["summary"])
        REFRESH["summary"].clear()


# ---------------------------------------------------------------- brctl dump (full): client.db + server.db items
RX = {
    "id": re.compile(r"\bi:<([^>]+)>"),
    "name": re.compile(r'n:"([^"]*)"\s+(doc|dir|pkg|symlink|alias|finder-bookmark|fault)?'),
    "size": re.compile(r"(?<![a-z])sz:(?:[\d.]+ [KMGT]?B \((\d+)\)|(\d+) bytes)"),
    "ctmt": re.compile(r"ct\{etag:\S+ mt:(\d+)"),
    "mt": re.compile(r"(?<![a-z])mt:(\d+)"),
    "bt": re.compile(r"\bbt:(\d+)"),
    "lu": re.compile(r"\blu:(\d+)"),
    "device": re.compile(r"\bdevice:(\d+)"),
    "quar": re.compile(r"quarantine:([\w|]+)"),
    "up": re.compile(r"\bup:([a-z-]+)"),
    "sc": re.compile(r"\bsc:(\w+)"),
    "pcs": re.compile(r"\bpcs:(\w+)"),
    "rk": re.compile(r"\brk:(\d+)"),
    "parent": re.compile(r"st\{p:<([^>]+)>"),
    "cont": re.compile(r"^\s*-{10,}(.+?)\[(\d+)\]-{10,}\s*$"),
    "sub": re.compile(r"^\s*>\s*([\w-]+)\{(.*)\}\s*$"),
    "syncup": re.compile(r"zone:(\d+) ([a-z-]+) attempts:(\d+) last:(.+?) next:(\S+) cleanup:(\S+?)\]"),
}


def ext_of(name):
    base = name.rsplit("/", 1)[-1]
    if "." in base[1:]:
        e = base.rsplit(".", 1)[-1].lower()
        if 0 < len(e) <= 8 and "{" not in e:
            return e
    return "(无)"


def parse_items(block, kind):
    cont_name, cont_id = None, None
    items, subs = [], []
    last = None
    for line in block.splitlines():
        m = RX["cont"].match(line)
        if m:
            cont_name, cont_id = m.group(1), int(m.group(2))
            continue
        m = RX["sub"].match(line)
        if m and last is not None:
            subs.append({"item": last, "kind": m.group(1), "detail": m.group(2)})
            last.setdefault("subs", []).append(m.group(1))
            continue
        mi = RX["id"].search(line)
        if not mi:
            continue
        it = {"id": mi.group(1), "c": cont_id, "cn": cont_name}
        mn = RX["name"].search(line)
        if mn:
            it["n"], it["t"] = mn.group(1), mn.group(2) or "?"
        else:
            it["n"], it["t"] = "", "root"
        ms = RX["size"].search(line)
        if ms:
            it["sz"] = int(ms.group(1) or ms.group(2))
        mm = RX["ctmt"].search(line) or RX["mt"].search(line)
        if mm and int(mm.group(1)) > 0:
            it["mt"] = int(mm.group(1))
        for k in ("bt", "lu", "device", "rk"):
            mk = RX[k].search(line)
            if mk:
                it[k] = int(mk.group(1))
        for k in ("quar", "up", "sc", "pcs", "parent"):
            mk = RX[k].search(line)
            if mk:
                it[k] = mk.group(1)
        it["kind"] = kind
        items.append(it)
        last = it
    return items, subs


def summarize_items(items, kind, now):
    files = [i for i in items if i["t"] in ("doc", "pkg")]
    c = {
        "total": len(items),
        "by_type": dict(collections.Counter(i["t"] for i in items).most_common()),
        "bytes": sum(i.get("sz", 0) for i in files),
    }
    conts = collections.defaultdict(lambda: {"count": 0, "files": 0, "bytes": 0, "dirs": 0})
    for i in items:
        k = (i["c"], i["cn"])
        conts[k]["count"] += 1
        if i["t"] in ("doc", "pkg"):
            conts[k]["files"] += 1
            conts[k]["bytes"] += i.get("sz", 0)
        elif i["t"] == "dir":
            conts[k]["dirs"] += 1
    c["containers"] = sorted(({"id": k[0], "name": k[1], **v} for k, v in conts.items()),
                             key=lambda x: -x["count"])
    exts = collections.defaultdict(lambda: [0, 0])
    for i in files:
        e = ext_of(i["n"])
        exts[e][0] += 1
        exts[e][1] += i.get("sz", 0)
    c["extensions"] = [{"ext": k, "count": v[0], "bytes": v[1]} for k, v in
                       sorted(exts.items(), key=lambda kv: -kv[1][0])[:25]]
    edges = [0, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000, float("inf")]
    labels = ["<10KB", "10–100KB", "100KB–1MB", "1–10MB", "10–100MB", "100MB–1GB", "≥1GB"]
    hist = [{"label": l, "count": 0, "bytes": 0} for l in labels]
    for i in files:
        s = i.get("sz", 0)
        for j in range(len(labels)):
            if edges[j] <= s < edges[j + 1]:
                hist[j]["count"] += 1
                hist[j]["bytes"] += s
                break
    c["size_hist"] = hist
    # 修改时间：近 60 天按天、近 36 个月按月
    day = collections.Counter()
    month = collections.Counter()
    for i in files:
        mt = i.get("mt")
        if not mt or mt > now + 86400:
            continue
        lt = time.localtime(mt)
        if now - mt < 60 * 86400:
            day[time.strftime("%Y-%m-%d", lt)] += 1
        month[time.strftime("%Y-%m", lt)] += 1
    days = [time.strftime("%Y-%m-%d", time.localtime(now - d * 86400)) for d in range(59, -1, -1)]
    c["mtime_days"] = [[d, day.get(d, 0)] for d in days]
    months = sorted(month)[-36:]
    c["mtime_months"] = [[m, month[m]] for m in months]
    c["devices"] = collections.Counter(i.get("device") for i in files if i.get("device")).most_common()  # 列表，保序
    slim = lambda i: {k: i.get(k) for k in ("id", "n", "t", "sz", "mt", "lu", "cn", "c", "device", "up", "sc", "quar", "pcs", "subs")}
    c["largest"] = [slim(i) for i in sorted(files, key=lambda i: -i.get("sz", 0))[:30]]
    c["recent"] = [slim(i) for i in sorted(files, key=lambda i: -(i.get("mt") or 0))[:40]]
    if kind == "client":
        c["up_states"] = dict(collections.Counter(i.get("up", "?") for i in items).most_common())
        c["scopes"] = dict(collections.Counter(i.get("sc", "?") for i in items).most_common())
        c["quarantine"] = dict(collections.Counter(q for i in files for q in (i.get("quar") or "").split("|") if q).most_common())
        c["recent_used"] = [slim(i) for i in sorted(files, key=lambda i: -(i.get("lu") or 0))[:30] if i.get("lu")]
        c["trash"] = [slim(i) for i in items if i.get("sc") == "trash"][:100]
    else:
        c["pcs"] = dict(collections.Counter(i.get("pcs", "?") for i in items).most_common())
    return c


# ---------------------------------------------------------------- 名称还原（macOS 26 的 {n} 脱敏）
# 思路：dump 里的 “D{7}s” 只保留首尾字符和中间长度，无法直接反推；但本机的真实文件就在
# ~/Library/Mobile Documents 下。按条目的父目录链逐级 listdir，只在同一目录内用
# “首尾字符 + 长度” 规则比对，就能唯一对上真实名称。只读：只 listdir / lstat，不打开文件；
# 遇到云端占位（dataless）目录不列（列它可能触发 fileproviderd 拉取目录），标为未解析。
MOBILE_DOCS = os.path.join(HOME, "Library/Mobile Documents")
SF_DATALESS = 0x40000000
REDACT_TOKEN = re.compile(r"(\{\d+\})")


def redaction_regex(red):
    out = ""
    for tok in REDACT_TOKEN.split(red):
        if not tok:
            continue
        m = re.fullmatch(r"\{(\d+)\}", tok)
        out += f".{{{m.group(1)}}}" if m else re.escape(tok)
    return re.compile("^" + out + "$", re.S)


def _forms(name):
    import unicodedata
    seen = []
    for f in (name, unicodedata.normalize("NFC", name), unicodedata.normalize("NFD", name)):
        if f not in seen:
            seen.append(f)
        b = f.encode("utf-16-le", "surrogatepass")   # NSString 按 UTF-16 计长度（emoji 占 2）
        u16 = "".join(chr(int.from_bytes(b[i:i + 2], "little")) for i in range(0, len(b), 2))
        if u16 not in seen:
            seen.append(u16)
    return seen


def redaction_match(rx, name):
    return any(rx.match(f) for f in _forms(name))


class Resolver:
    def __init__(self, items):
        self.by_id = {}
        for i in items:
            self.by_id.setdefault((i["c"], i["id"]), i)
        self.ls_cache = {}
        self.path_cache = {}
        self.cont_cache = {}
        self.stats = collections.Counter()
        try:
            self.md = {f.replace("~", "."): f for f in os.listdir(MOBILE_DOCS)}
        except OSError:
            self.md = {}

    def container(self, cn):
        if cn in self.cont_cache:
            return self.cont_cache[cn]
        if not cn:
            return None
        if "{" not in cn:
            hit = [cn] if cn in self.md else []
        else:
            rx = redaction_regex(cn)
            hit = [d for d in self.md if redaction_match(rx, d)]
        r = {"real": hit[0], "path": os.path.join(MOBILE_DOCS, self.md[hit[0]])} if len(hit) == 1 else \
            {"real": None, "candidates": hit[:5]}
        self.cont_cache[cn] = r
        return r

    def listdir(self, path):
        if path in self.ls_cache:
            return self.ls_cache[path]
        res = None
        try:
            st = os.lstat(path)
            if st.st_flags & SF_DATALESS:
                res = "dataless"
            else:
                with os.scandir(path) as it:
                    res = [(e.name, e.is_dir(follow_symlinks=False), e.is_symlink()) for e in it]
        except OSError:
            res = None
        self.ls_cache[path] = res
        return res

    def path(self, item, depth=0):
        """返回 (状态, 真实路径或说明)。状态：ok / ambiguous / dataless / missing / unknown"""
        key = (item["c"], item["id"])
        if key in self.path_cache:
            return self.path_cache[key]
        r = self._path(item, depth)
        self.path_cache[key] = r
        return r

    def _path(self, item, depth):
        if depth > 60:
            return ("unknown", "层级过深")
        if item["id"].startswith("root["):
            c = self.container(item["cn"])
            return ("ok", c["path"]) if c and c.get("path") else ("unknown", "找不到资料库目录")
        par = self.by_id.get((item["c"], item.get("parent")))
        if not par:
            return ("unknown", "父目录不在 client.db 里")
        st, ppath = self.path(par, depth + 1)
        if st != "ok":
            return (st, ppath)
        entries = self.listdir(ppath)
        if entries == "dataless":
            return ("dataless", ppath)
        if entries is None:
            return ("missing", ppath)
        name = item.get("n") or ""
        if "{" not in name:
            hits = [e for e in entries if e[0] in _forms(name) or name in _forms(e[0])]
        else:
            rx = redaction_regex(name)
            hits = [e for e in entries if redaction_match(rx, e[0])]
        if len(hits) > 1:   # 同目录撞车：用类型、再用大小区分
            want_dir = item.get("t") == "dir"
            hits = [e for e in hits if e[1] == want_dir] or hits
        if len(hits) > 1 and item.get("sz") is not None:
            sized = []
            for e in hits:
                try:
                    if os.lstat(os.path.join(ppath, e[0])).st_size == item["sz"]:
                        sized.append(e)
                except OSError:
                    pass
            hits = sized or hits
        if len(hits) == 1:
            return ("ok", os.path.join(ppath, hits[0][0]))
        if hits:
            return ("ambiguous", " | ".join(h[0] for h in hits[:4]))
        return ("missing", ppath)

    def annotate(self, row):
        """给要展示的条目加 real（真实名）/ rpath（相对 Mobile Documents 的路径）/ rs（解析状态）"""
        if not row or "id" not in row or row.get("_done"):
            return row
        it = self.by_id.get((row.get("c"), row.get("id")))
        c = self.container(row.get("cn"))
        if c and c.get("real"):
            row["rcn"] = c["real"]
        if it:
            st, val = self.path(it)
            self.stats[st] += 1
            row["rs"] = st
            if st == "ok":
                row["real"] = os.path.basename(val)
                row["rpath"] = os.path.relpath(val, MOBILE_DOCS)
            elif st == "ambiguous":
                row["cands"] = val
        row["_done"] = True
        return row


def analyze_full(text):
    now = time.time()
    si = text.find("\n    server items")
    ci = text.find("\n    client items")
    se = text.find("\n    scheduling sync contexts")
    if si < 0 or ci < 0:
        raise ValueError("dump 结构不认识：找不到 server items / client items")
    server, _ = parse_items(text[si:ci], "server")
    client, subs = parse_items(text[ci:se if se > 0 else len(text)], "client")
    r = {"taken": now, "server": summarize_items(server, "server", now),
         "client": summarize_items(client, "client", now)}
    # 子任务（client.db 上挂着的 sync-up / downloader / … 队列）
    sub_rows = []
    for s in subs:
        it = s["item"]
        row = {"kind": s["kind"], "detail": s["detail"][:400], "n": it.get("n"), "t": it.get("t"),
               "cn": it.get("cn"), "c": it.get("c"), "sz": it.get("sz"), "up": it.get("up"),
               "sc": it.get("sc"), "id": it.get("id")}
        m = RX["syncup"].search(s["detail"])
        if m:
            row.update(zone=int(m.group(1)), state=m.group(2), attempts=int(m.group(3)),
                       last=m.group(4), next=m.group(5))
        sub_rows.append(row)
    r["queues"] = {"by_kind": dict(collections.Counter(s["kind"] for s in subs).most_common()),
                   "rows": sub_rows[:500]}
    # server 与 client 的差异（按条目 id，逐容器比较）
    sids = collections.defaultdict(set)
    cids = collections.defaultdict(set)
    sname, cname = {}, {}
    for i in server:
        if i["t"] != "root":
            sids[i["c"]].add(i["id"]); sname[(i["c"], i["id"])] = i
    for i in client:
        if i["t"] != "root":  # 每个资料库的虚拟根只存在于本地，不参与比较
            cids[i["c"]].add(i["id"]); cname[(i["c"], i["id"])] = i
    diff, only_s, only_c = [], [], []
    for cid in set(sids) | set(cids):
        a, b = sids.get(cid, set()), cids.get(cid, set())
        os_, oc = a - b, b - a
        if os_ or oc:
            nm = next(iter([x["cn"] for x in server if x["c"] == cid][:1] or [x["cn"] for x in client if x["c"] == cid][:1]), str(cid))
            diff.append({"id": cid, "name": nm, "server": len(a), "client": len(b),
                         "only_server": len(os_), "only_client": len(oc)})
            only_s += [sname[(cid, x)] for x in list(os_)[:20]]
            only_c += [cname[(cid, x)] for x in list(oc)[:20]]
    keep = lambda i: {k: i.get(k) for k in ("id", "n", "t", "sz", "mt", "cn", "c", "up", "sc", "subs")}
    r["diff"] = {"containers": sorted(diff, key=lambda d: -(d["only_server"] + d["only_client"])),
                 "only_server": [keep(i) for i in only_s[:100]],
                 "only_client": [keep(i) for i in only_c[:100]],
                 "only_server_total": sum(d["only_server"] for d in diff),
                 "only_client_total": sum(d["only_client"] for d in diff)}
    # 名称还原：只对页面上展示的条目做（几百条），不扫全库
    t0 = time.time()
    res = Resolver(client)
    shown = []
    for k in ("largest", "recent", "recent_used", "trash"):
        shown += r["client"].get(k) or []
    shown += r["queues"]["rows"] + r["diff"]["only_client"]
    for row in shown:
        res.annotate(row)
        row.pop("_done", None)
    for row in r["server"].get("largest", []) + r["server"].get("recent", []) + r["diff"]["only_server"]:
        c = res.container(row.get("cn"))
        if c and c.get("real"):
            row["rcn"] = c["real"]
    names = {}
    for cont in r["client"]["containers"] + r["server"]["containers"] + r["diff"]["containers"]:
        c = res.container(cont.get("name"))
        if c and c.get("real"):
            names[cont["name"]] = c["real"]
    r["names"] = {"containers": names, "stats": dict(res.stats), "listed_dirs": len(res.ls_cache),
                  "skipped_dataless": sum(1 for v in res.ls_cache.values() if v == "dataless"),
                  "took": round(time.time() - t0, 2)}
    return r


def full_loop():
    time.sleep(8)
    while True:
        S.set("full_running", True)
        S.set("full_started", time.time())
        out, dt, rc = run(["brctl", "dump"], timeout=600, lock=True)
        S.set("full_running", False)
        win = (S.get("dump_windows") or [])[-19:] + [[S.get("full_started"), time.time()]]
        S.set("dump_windows", win)
        if out:
            try:
                t0 = time.time()
                r = analyze_full(out)
                r["took_dump"] = round(dt, 1)
                r["took_parse"] = round(time.time() - t0, 1)
                r["dump_bytes"] = len(out)
                r["dump_lines"] = out.count("\n")
                with S.lock:
                    S.items = r
                    S.items_version += 1
                S.set("full_meta", {"taken": r["taken"], "took": r["took_dump"], "version": S.items_version})
                S.err("full", None)
            except Exception:  # noqa
                S.err("full", traceback.format_exc(limit=3))
        else:
            S.err("full", f"brctl dump 失败 rc={rc}")
        del out
        REFRESH["full"].wait(INTERVAL["full"])
        REFRESH["full"].clear()


# ---------------------------------------------------------------- logs
LOGS = collections.deque(maxlen=3000)
LOG_SEQ = [0]
LOG_LOCK = threading.Lock()
MINUTES = collections.OrderedDict()   # "HH:MM" epoch-minute -> Counter(level)
PATTERNS = {}                          # normalized -> {count, first, last, level, sample, category}
OPS = collections.deque(maxlen=300)
COMPONENTS = collections.Counter()
NORM = [
    (re.compile(r"0x[0-9a-fA-F]+"), "0x…"),
    (re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", re.I), "<uuid>"),
    (re.compile(r"\d+"), "#"),
]
OP_RX = re.compile(r"(Starting|Finished|Cancel\w*|Failed)\s+operation\s+<(\w+):.*?shortened-name=([^,}]+)")
BRC_RX = re.compile(r"\b(BRC\w+|BR\w+Operation|CK\w+Operation)\b")


def level_of(e):
    mt = (e.get("messageType") or "").lower()
    msg = e.get("eventMessage") or ""
    if mt == "fault" or "[CRIT]" in msg or "[FAULT]" in msg:
        return "fault"
    if mt == "error" or "[ERROR]" in msg:
        return "error"
    if "[WARNING]" in msg or "[WARN]" in msg:
        return "warning"
    if mt in ("debug",):
        return "debug"
    if mt == "info":
        return "info"
    return "default"


def ingest(e):
    if "eventMessage" not in e or "timestamp" not in e:
        return
    lv = level_of(e)
    ts = e["timestamp"]
    try:
        t = time.mktime(time.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")) + float("0." + ts[20:26] if len(ts) > 20 else 0)
    except Exception:  # noqa
        t = time.time()
    msg = e["eventMessage"]
    rec = {"t": t, "ts": ts[11:23], "lv": lv, "sub": e.get("subsystem") or "", "cat": e.get("category") or "",
           "msg": msg[:2000], "tid": e.get("threadID")}
    with LOG_LOCK:
        LOG_SEQ[0] += 1
        rec["seq"] = LOG_SEQ[0]
        LOGS.append(rec)
        minute = int(t // 60) * 60
        MINUTES.setdefault(minute, collections.Counter())[lv] += 1
        while len(MINUTES) > 180:
            MINUTES.popitem(last=False)
        if lv in ("error", "fault", "warning"):
            norm = msg[:220]
            for rx, rep in NORM:
                norm = rx.sub(rep, norm)
            p = PATTERNS.get(norm)
            if not p:
                p = PATTERNS[norm] = {"count": 0, "first": t, "level": lv, "cat": rec["cat"], "sub": rec["sub"]}
            p["count"] += 1
            p["last"] = t
            p["sample"] = msg[:1500]
            if len(PATTERNS) > 400:
                oldest = min(PATTERNS, key=lambda k: PATTERNS[k]["last"])
                PATTERNS.pop(oldest, None)
        m = OP_RX.search(msg)
        if m:
            own = any(a <= t <= b for a, b in OWN_WINDOWS) and "Quota" in m.group(3)
            OPS.append({"t": t, "ts": rec["ts"], "phase": m.group(1), "op": m.group(2), "name": m.group(3).strip(), "own": own})
        for comp in set(BRC_RX.findall(msg)):
            COMPONENTS[comp] += 1


def parse_ndjson_lines(stream):
    for line in stream:
        if isinstance(line, bytes):
            line = line.decode("utf-8", "replace")
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except Exception:  # noqa
            continue


PRED = 'process == "bird"'


UPFAIL_RX = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*?(failed uploading (\d+) items|\] uploading (\d+) documents)")


def upload_fail_loop():
    """bird 上传整批失败后会从零重来；大文件可能因此永远传不完。日志流只看 60 分钟不够，单独回看 24 小时。"""
    while True:
        out, _, _ = run(["/usr/bin/log", "show", "--last", "24h", "--style", "compact", "--predicate",
                         'process == "bird" AND (eventMessage CONTAINS "failed uploading" OR eventMessage CONTAINS "] uploading ")'],
                        timeout=180)
        events = []
        for line in out.splitlines():
            m = UPFAIL_RX.match(line)
            if not m:
                continue
            t = parse_local(m.group(1))
            if m.group(3):
                events.append({"t": t, "kind": "fail", "n": int(m.group(3))})
            elif m.group(4):
                events.append({"t": t, "kind": "start", "n": int(m.group(4))})
        S.set("upload_events", events[-300:])
        time.sleep(INTERVAL["uploadfail"])


def log_backfill():
    out, _, _ = run(["/usr/bin/log", "show", "--last", "60m", "--info", "--style", "ndjson",
                     "--predicate", PRED], timeout=120)
    for e in parse_ndjson_lines(out.splitlines()):
        ingest(e)
    S.set("log_backfill", {"done": True, "events": LOG_SEQ[0]})


LOG_PROC = [None]


def log_stream_loop():
    log_backfill()
    while True:
        cmd = ["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate", PRED]
        COMMANDS_USED[" ".join(cmd)] = COMMANDS_USED.get(" ".join(cmd), 0) + 1
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            LOG_PROC[0] = p
            S.set("log_stream", {"running": True, "since": time.time()})
            for e in parse_ndjson_lines(p.stdout):
                ingest(e)
            p.wait()
        except Exception:  # noqa
            S.err("logstream", traceback.format_exc(limit=2))
        S.set("log_stream", {"running": False, "since": time.time()})
        time.sleep(3)


def log_stats():
    now = time.time()
    with LOG_LOCK:
        cur = int(now // 60) * 60
        mins = []
        for k in range(119, -1, -1):
            m = cur - k * 60
            cnt = MINUTES.get(m, {})
            mins.append([m, {lv: cnt.get(lv, 0) for lv in ("fault", "error", "warning", "info", "default", "debug")}])
        pats = sorted(({"pattern": k, **v} for k, v in PATTERNS.items()), key=lambda p: -p["last"])
        recent = [x for x in LOGS if now - x["t"] < 600]
        lv10 = collections.Counter(x["lv"] for x in recent)
        cats = collections.Counter(f'{x["sub"]}/{x["cat"]}'.strip("/") or "(无)" for x in recent)
        last60 = [x for x in LOGS if now - x["t"] < 60]
        return {
            "minutes": mins, "patterns": pats[:120], "ops": list(OPS)[-80:],
            "components": COMPONENTS.most_common(25), "last10m": dict(lv10),
            "categories10m": cats.most_common(15), "rate60s": len(last60), "seq": LOG_SEQ[0],
            "errors10m": lv10.get("error", 0) + lv10.get("fault", 0),
            "last_event": LOGS[-1]["t"] if LOGS else None,
        }


# ---------------------------------------------------------------- health & "doing now"
def ago(sec):
    if sec is None:
        return "未知"
    sec = int(sec)
    if sec < 60:
        return f"{sec} 秒前"
    if sec < 3600:
        return f"{sec // 60} 分钟前"
    if sec < 86400:
        return f"{sec // 3600} 小时前"
    return f"{sec // 86400} 天前"


def parse_local(s):
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%d %H:%M:%S"))
    except Exception:  # noqa
        return None


def assess(state, ls):
    checks = []
    add = lambda lv, title, msg: checks.append({"level": lv, "title": title, "msg": msg})
    procs = state.get("procs") or {}
    bird = procs.get("bird") or {}
    summ = state.get("summary") or {}
    now = time.time()
    if not bird.get("running"):
        add("crit", "bird 进程", "bird 没有在运行（launchd 一般会自动拉起）")
    else:
        add("ok", "bird 进程", f"PID {bird.get('pid')}，已运行 {ago(bird.get('uptime')).replace('前', '')}")
    sysd = summ.get("system") or {}
    if sysd:
        net = sysd.get("network", "")
        add("ok" if "online" in net else "crit", "网络", net or "未知")
        disk = sysd.get("disk", "")
        add("ok" if disk.startswith("healthy") else "warn", "磁盘", disk)
        pw = sysd.get("power", "")
        add("ok" if pw.startswith("healthy") else "warn", "电源", pw)
    hr = summ.get("health_report") or {}
    bad = {k: v for k, v in hr.items() if v.strip() != "none"}
    if hr:
        add("crit" if bad else "ok", "SyncHealthReport",
            "全部为 none" if not bad else "；".join(f"{k}={v}" for k, v in bad.items()))
    z = (summ.get("zone") or {}).get("detail") or {}
    ls_t = parse_local(z.get("last-sync", "")) if z.get("last-sync") else None
    if ls_t:
        age = now - ls_t
        add("ok" if age < 6 * 3600 else "warn", "最近一次同步",
            f"{z.get('last-sync')}（{ago(age)}）" + ("，已追平服务器" if z.get("caught-up") else "，尚未追平"))
    up = summ.get("sync_up_scheduled") or 0
    items = S.items
    if up and items:
        # 已核实的无害模式：App 资料库的空 Documents 占位目录，资料库自己标着 no-documents，
        # bird 有预算、状态 ready 却从不尝试——是它主动跳过，不是传不上去。
        libs = {l["id"]: l for l in summ.get("app_libraries") or []}
        benign, stuck, failing = 0, 0, 0
        for r in items["queues"]["rows"]:
            if r.get("kind") != "sync-up":
                continue
            lib = libs.get(r.get("c")) or {}
            if r.get("t") == "dir" and str(r.get("id", "")).startswith("documents[") and not r.get("sz") \
                    and "no-documents" in lib.get("flags", []):
                benign += 1
                continue
            if r.get("attempts", 0) >= 3:
                failing += 1
            hrs = None
            if "h ago" in (r.get("last") or ""):
                try:
                    hrs = float(r["last"].split("h")[0])
                except ValueError:
                    pass
            if hrs and hrs > 24:
                stuck += 1
        real = up - benign
        parts = []
        if benign:
            parts.append(f"{benign} 个是 App 资料库的空 Documents 占位目录（资料库标着 no-documents，bird 主动跳过，无害）")
        if real > 0:
            parts.append(f"{real} 个真正待上传")
        if stuck:
            parts.append(f"其中 {stuck} 个已排队超过 24 小时")
        if failing:
            parts.append(f"{failing} 个已重试 3 次以上")
        add("warn" if (stuck or failing or real > 500) else "ok", "待上传队列", f"共 {up} 个：" + "；".join(parts))
    elif up:
        add("ok", "待上传队列", f"{up} 个条目排队待上传（完整 dump 完成后会细分）")
    else:
        add("ok", "待上传队列", "空")
    evs = state.get("upload_events") or []
    fails6 = [e for e in evs if e["kind"] == "fail" and now - e["t"] < 6 * 3600]
    fails24 = [e for e in evs if e["kind"] == "fail"]
    if len(fails6) >= 2:
        sizes = [e["n"] for e in fails6]
        add("crit" if len(fails6) >= 4 else "warn", "上传反复失败",
            f"近 6 小时整批上传失败 {len(fails6)} 次（24 小时 {len(fails24)} 次），每批 {min(sizes)}–{max(sizes)} 个文件；"
            "bird 失败后从零重传，大文件可能永远传不完——看「错误」页的失败时间线")
    elif fails24:
        add("ok", "上传失败", f"24 小时内整批上传失败 {len(fails24)} 次，近 6 小时没有")
    e10 = ls.get("errors10m", 0)
    add("ok" if e10 < 20 else ("warn" if e10 < 200 else "crit"), "近 10 分钟错误日志", f"{e10} 条")
    cpu = bird.get("cpu", 0)
    hist = list(S.hist.get("cpu.bird", []))[-30:]
    avg = sum(p[1] for p in hist) / len(hist) if hist else 0
    fm = state.get("full_meta") or {}
    own = state.get("full_running") or (fm.get("taken") and now - fm["taken"] < 45)
    if own:
        add("ok", "CPU（近 1 分钟均值）", f"{avg:.1f}%，当前 {cpu:.1f}%——本监控器刚触发了完整 brctl dump，bird 正在为它读库输出，属预期负载")
    else:
        add("ok" if avg < 30 else ("warn" if avg < 80 else "crit"), "CPU（近 1 分钟均值）", f"{avg:.1f}%，当前 {cpu:.1f}%")
    fp = bird.get("footprint", 0)
    add("ok" if fp < 500e6 else "warn", "内存占用", f"{fp / 1e6:.0f} MB")
    files = {f["name"]: f["size"] for f in (state.get("dbfiles") or {}).get("files", [])}
    wal = files.get("client.db-wal", 0)
    add("ok" if wal < 64e6 else "warn", "client.db WAL", f"{wal / 1e6:.1f} MB" + ("（偏大，说明检查点没跟上）" if wal >= 64e6 else ""))
    q = (state.get("quota") or {}).get("remaining")
    if q is not None:
        add("ok" if q > 5e9 else ("warn" if q > 1e9 else "crit"), "iCloud 剩余空间", f"{q / 1e9:.1f} GB（brctl quota 实时值）")
    elif summ.get("available_quota"):
        add("ok", "iCloud 剩余空间", f"实时值查询中；client_state 缓存值 {summ['available_quota'] / 1e9:.1f} GB（可能过时）")
    if state.get("errors"):
        add("warn", "监控器自身", "部分采集器出错：" + ", ".join(state["errors"].keys()))
    worst = "crit" if any(c["level"] == "crit" for c in checks) else ("warn" if any(c["level"] == "warn" for c in checks) else "ok")
    return worst, checks


def doing_now(state, ls):
    procs = state.get("procs") or {}
    bird = procs.get("bird") or {}
    summ = state.get("summary") or {}
    if not bird.get("running"):
        return {"headline": "bird 没有运行", "busy": False, "details": []}
    details = []
    busy = False
    cpu = bird.get("cpu", 0)
    if cpu > 5:
        busy = True
        details.append(f"CPU {cpu:.0f}%")
    io = bird.get("read_rate", 0) + bird.get("write_rate", 0)
    if io > 512 * 1024:
        busy = True
        details.append(f"磁盘读写 {io / 1048576:.1f} MB/s")
    net = state.get("net") or {}
    nb = sum((v["in"] + v["out"]) for k, v in net.items() if k in ("cloudd", "nsurlsessiond"))
    if nb > 50 * 1024:
        busy = True
        details.append(f"iCloud 网络 {nb / 1048576:.2f} MB/s（cloudd/nsurlsessiond）")
    now = time.time()
    recent = [o for o in ls.get("ops", []) if now - o["t"] < 120]
    ops = [o for o in recent if not o.get("own")]
    if ops:
        busy = True
        names = collections.Counter(o["name"] for o in ops)
        details.append("最近 2 分钟 CloudKit 操作：" + "、".join(f"{n}×{c}" for n, c in names.most_common(4)))
    elif recent:
        details.append(f"最近 2 分钟有 {len(recent)} 条配额查询操作，是本监控器的 brctl quota 触发的（不算 bird 在忙）")
    pend = summ.get("pending") or {}
    for k in ("downloads", "uploads", "reader", "apply"):
        v = pend.get(k, "")
        if v and "not dumping" not in v and v not in ("none", "idle"):
            busy = True
            details.append(f"{k}: {v[:80]}")
    if summ.get("global_progress") and summ["global_progress"] != "none":
        busy = True
        details.append(f"全局进度：{summ['global_progress']}")
    z = (summ.get("zone") or {}).get("detail") or {}
    client_state = z.get("client")
    lsf = (state.get("lsof") or {}).get("files", [])
    doc_files = [f for f in lsf if "/Mobile Documents/" in f.get("name", "") or "/CloudStorage/" in f.get("name", "")]
    if doc_files:
        busy = True
        details.append(f"正打开着 {len(doc_files)} 个 iCloud 文件")
    if state.get("full_running"):
        details.insert(0, "本监控器正在执行完整 brctl dump（bird 在读 client.db / server.db 并输出，约 20 秒，CPU 升高属预期）")
        busy = True
    if busy:
        head = "正在工作：" + (details[0] if details else "")
        if state.get("full_running") and len(details) <= 3 and not ops:
            head = "正在为监控器输出完整 dump（预期负载）"
    else:
        lst = z.get("last-sync")
        head = "空闲" + (f"（客户端 {client_state}）" if client_state else "") + \
               (f"，最近一次同步 {ago(now - parse_local(lst))}" if lst and parse_local(lst) else "")
    return {"headline": head, "busy": busy, "details": details, "rate60s": ls.get("rate60s", 0)}


# ---------------------------------------------------------------- HTTP
def hist_series(prefix_list, maxpts=450):
    with S.lock:
        return {k: list(S.hist.get(k, []))[-maxpts:] for k in prefix_list}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "static", "index.html"), "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/api/state":
            with S.lock:
                state = json.loads(json.dumps(S.data, default=str))
                state["items_version"] = S.items_version
            ls = log_stats()
            state["health"], state["checks"] = assess(state, ls)
            state["doing"] = doing_now(state, ls)
            state["logstats"] = ls
            state["now"] = time.time()
            state["host"] = HOST
            state["os_version"] = OS_VERSION
            state["intervals"] = INTERVAL
            state["commands"] = [{"cmd": k, "n": v} for k, v in COMMANDS_USED.items()]
            return self.send(200, state)
        if u.path == "/api/history":
            keys = [f"{m}.{n}" for m in ("cpu", "mem") for n in TRACKED] + \
                   ["io.read", "io.write", "net.in", "net.out", "wal.client", "wal.server", "pending.up"]
            return self.send(200, hist_series(keys))
        if u.path == "/api/items":
            with S.lock:
                return self.send(200, {"version": S.items_version, "items": S.items})
        if u.path == "/api/logs":
            after = int((q.get("after") or ["0"])[0])
            with LOG_LOCK:
                rows = [x for x in LOGS if x["seq"] > after][-800:]
            return self.send(200, {"rows": rows, "seq": LOG_SEQ[0]})
        if u.path == "/api/raw":
            kind = (q.get("kind") or ["summary"])[0]
            return self.send(200, S.raw.get(kind, "(尚未采集)"), "text/plain; charset=utf-8")
        self.send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/refresh":
            kind = (parse_qs(u.query).get("kind") or ["summary"])[0]
            if kind in REFRESH:
                REFRESH[kind].set()
                return self.send(200, {"ok": True, "kind": kind})
        self.send(400, {"error": "bad request"})


def main():
    for fn in (proc_loop, net_loop, files_loop, lsof_loop, status_loop, quota_loop,
               summary_loop, full_loop, log_stream_loop, upload_fail_loop):
        threading.Thread(target=fn, daemon=True, name=fn.__name__).start()

    def bye(*_):
        if LOG_PROC[0]:
            LOG_PROC[0].terminate()
        os._exit(0)

    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"BiRD Monitor → http://127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        # 解析离线 dump 文本（来自 brctl dump 的输出文件），用于开发验证
        txt = ANSI.sub("", open(sys.argv[2], encoding="utf-8", errors="replace").read())
        if "server items" in txt and "client items" in txt and len(txt) > 5_000_000:
            r = analyze_full(txt)
            print(json.dumps({k: (v if k != "queues" else v["by_kind"]) for k, v in r.items() if k in ("queues",)}, ensure_ascii=False))
            print("client", r["client"]["total"], r["client"]["by_type"], r["client"]["bytes"], r["client"]["up_states"])
            print("server", r["server"]["total"], r["server"]["by_type"], r["server"]["pcs"])
            print("diff", r["diff"]["only_server_total"], r["diff"]["only_client_total"], r["diff"]["containers"][:5])
            print("ext", r["client"]["extensions"][:8])
            print("q0", r["queues"]["rows"][:2])
        s = parse_summary(txt)
        print(json.dumps({k: v for k, v in s.items() if k not in ("app_libraries",)}, ensure_ascii=False, indent=1)[:4000])
        print("app_libraries", len(s["app_libraries"]), s["app_libraries"][:2])
    else:
        main()

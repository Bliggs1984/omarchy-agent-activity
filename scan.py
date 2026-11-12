#!/usr/bin/env python3
"""Agent Activity scanner for the Omarchy bar.

Finds AI coding agents (Claude Code, Codex, Gemini CLI, ...) in /proc, works
out which processes each one started, describes those in plain English, and
prints one JSON line to stdout whenever what the panel would show changes.

Performance is the priority:
- One read of /proc/<pid>/stat per process per tick. That single file carries
  the parent, CPU ticks, start time and resident memory.
- Command lines and environments are read once per process and cached, and
  only for agents, their descendants, and orphans that might belong to one.
- Slow ticks (5 s) while the panel is closed, fast (2 s) while it is open.
  The shell says which by writing "open" or "closed" on stdin; EOF means the
  shell went away, so we exit.

Nothing is written to disk. Displayed text is masked for secrets (see redact()).
"""

import json
import os
import re
import select
import sqlite3
import sys
import time

CLK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
NCPU = os.cpu_count() or 1
MY_UID = os.getuid()
FAST, SLOW = 2.0, 5.0
DONE_HOLD = 20.0          # seconds a finished task stays on the panel
MAX_TASKS_PER_AGENT = 8
MAX_CMD = 8192            # longest command line we try to understand
T3_DB = os.path.expanduser("~/.t3/userdata/statev2.sqlite")

# comm (or script basename for node/bun/python launchers) -> display name
AGENTS = {
    "claude": "Claude Code",
    "codex": "Codex",
    "gemini": "Gemini CLI",
    "opencode": "OpenCode",
    "kimi": "Kimi Code",
    "aider": "Aider",
    "goose": "Goose",
    "crush": "Crush",
    "amp": "Amp",
    "cursor-agent": "Cursor Agent",
    "copilot": "Copilot CLI",
    "qwen": "Qwen Code",
    "droid": "Droid",
    "grok": "Grok CLI",
}
LAUNCHERS = {"node", "bun", "deno", "python", "python3", "MainThread"}
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "ash"}

HOSTS = [  # ancestor comm prefix -> host app label
    ("t3code", "T3 Code"), ("T3-Code", "T3 Code"), ("code", "VS Code"),
    ("codium", "VSCodium"), ("cursor", "Cursor"), ("zed", "Zed"),
    ("alacritty", "Terminal"), ("foot", "Terminal"), ("kitty", "Terminal"),
    ("ghostty", "Terminal"), ("wezterm", "Terminal"), ("konsole", "Terminal"),
    ("gnome-terminal", "Terminal"), ("tmux", "tmux"), ("zellij", "Zellij"),
    ("sshd", "SSH"),
]


# --------------------------------------------------------------------------
# Secret masking. Everything that reaches the panel goes through here.
# --------------------------------------------------------------------------
_SECRET_NAME = r"[A-Za-z0-9_\-]*(?:pass(?:word|wd)?|secret|token|api[_\-]?key|apikey|auth|credential|private[_\-]?key|access[_\-]?key|session)[A-Za-z0-9_\-]*"
_REDACTIONS = [
    # NAME=value, --name=value, --name value, "name": "value", name: value
    re.compile(r"(?i)(\b" + _SECRET_NAME + r"\b[\"']?\s*(?:=|:|\s)\s*[\"']?)([^\s\"'&;|]+)"),
    # Authorization headers
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)?\s*)(\S+)"),
    # user:password@ in URLs
    re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)"),
]
_TOKEN_SHAPES = re.compile(
    r"\b(?:sk-[A-Za-z0-9_\-]{12,}|sk-ant-[A-Za-z0-9_\-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"
    r"|glpat-[A-Za-z0-9_\-]{16,}|hf_[A-Za-z0-9]{20,})\b")


def redact(text):
    if not text:
        return text
    text = _TOKEN_SHAPES.sub("•••", text)
    text = _REDACTIONS[1].sub(lambda m: m.group(1) + "•••", text)   # headers before the generic rule
    text = _REDACTIONS[0].sub(lambda m: m.group(1) + "•••", text)
    text = _REDACTIONS[2].sub(lambda m: m.group(1) + "•••" + m.group(3), text)
    return text


# --------------------------------------------------------------------------
# Plain-English descriptions of commands
# --------------------------------------------------------------------------
_CLAUDE_EVAL = re.compile(r"\beval '((?:[^']|'\"'\"')*)'")
_SKIP_WORDS = {"sudo", "env", "nice", "ionice", "time", "command", "exec", "builtin", "nohup", "stdbuf"}
_SETUP = re.compile(r"^(?:cd|export|source|\.|set|shopt|unset|unalias|trap|true|:|local|declare|ulimit|umask|pushd|popd|eval)$")


def unwrap_shell(args, depth=0):
    """Return the script a shell was asked to run, or None."""
    if not args or depth > 3:
        return None
    prog = os.path.basename(args[0])
    if prog not in SHELLS:
        return None
    for i, a in enumerate(args[1:], 1):
        if a in ("-c", "-lc", "-ic", "-cl") and i + 1 < len(args):
            script = args[i + 1][:MAX_CMD]
            m = _CLAUDE_EVAL.search(script)          # Claude Code's Bash tool
            if m:
                return m.group(1).replace("'\"'\"'", "'")
            return script
    return None


def split_commands(script):
    """Split a shell script into simple commands (good enough, not a parser)."""
    out, cur, q, i = [], [], None, 0
    while i < len(script):
        c = script[i]
        if q:
            cur.append(c)
            if c == q:
                q = None
            elif c == "\\" and q == '"' and i + 1 < len(script):
                cur.append(script[i + 1]); i += 1
        elif c in "'\"":
            q = c; cur.append(c)
        elif c in ";|&\n(){}":
            if cur and "".join(cur).strip():
                out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur and "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def words(cmd):
    toks, cur, q = [], "", None
    for c in cmd:
        if q:
            if c == q:
                q = None
            else:
                cur += c
        elif c in "'\"":
            q = c
        elif c.isspace():
            if cur:
                toks.append(cur); cur = ""
        else:
            cur += c
    if cur:
        toks.append(cur)
    return toks


def main_words(cmd):
    """Drop VAR=val prefixes and wrappers like sudo/env/timeout."""
    w = words(cmd)
    if w and w[0] in ("for", "select", "case", "done", "fi", "esac", "function"):
        return []
    while w:
        head = w[0]
        if head in ("do", "then", "else", "elif", "if", "while", "until", "!"):
            w = w[1:]
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head):
            w = w[1:]
        elif head in _SKIP_WORDS:
            w = w[1:]
            while w and w[0].startswith("-"):
                w = w[1:]
        elif head == "timeout":
            w = w[1:]
            while w and (w[0].startswith("-") or re.match(r"^\d", w[0])):
                w = w[1:]
        else:
            break
    return w


def _arg(w, n=1):
    rest = [a for a in w[1:] if not a.startswith("-")]
    return rest[n - 1] if len(rest) >= n else ""


def _base(p):
    return os.path.basename(p.rstrip("/")) or p


def describe_words(w):
    if not w:
        return None
    prog = _base(w[0])
    sub = _arg(w)
    if prog in SHELLS:
        inner = unwrap_shell(w)
        if inner:
            return describe_script(inner)
        if sub:
            return "Running " + _base(sub)
        return "Shell"
    if _SETUP.match(prog) or prog in ("echo", "printf", "sleep", "wait", "test", "[", "[[", "read"):
        return {"sleep": "Waiting", "wait": "Waiting for jobs"}.get(prog)
    if prog == "git":
        return "Git " + sub if sub else "Git"
    if prog == "gh":
        return ("GitHub " + " ".join(a for a in w[1:3] if not a.startswith("-"))).strip()
    if prog == "cargo":
        return {"test": "Running Rust tests", "build": "Building Rust project", "run": "Running Rust program",
                "check": "Checking Rust code", "clippy": "Linting Rust code", "fmt": "Formatting Rust code"}.get(sub, "Cargo " + sub)
    if prog in ("npm", "pnpm", "yarn", "bun"):
        if sub in ("run", "run-script"):
            return prog + " run " + _arg(w, 2)
        if sub in ("test", "t"):
            return "Running JS tests"
        if sub in ("install", "i", "add", "ci"):
            return "Installing packages"
        if sub in ("x", "exec", "dlx") or prog == "bun" and sub.endswith((".ts", ".js")):
            return "Running " + _base(_arg(w, 2) or sub)
        return prog + " " + sub if sub else prog
    if prog in ("npx", "bunx", "uvx", "pnpx"):
        return "Running " + _base(sub) if sub else prog
    if prog.startswith("python") or prog in ("node", "deno", "ruby", "perl", "php"):
        if "-m" in w:
            mod = w[w.index("-m") + 1] if w.index("-m") + 1 < len(w) else ""
            return {"pytest": "Running Python tests", "pip": "Installing packages", "http.server": "Serving files"}.get(mod, "Running " + mod)
        if "-c" in w or "-e" in w or "--eval" in w or not sub or sub.startswith("$"):
            return {"node": "Node script", "deno": "Deno script"}.get(prog, "Python script" if prog.startswith("python") else prog + " script")
        return "Running " + _base(sub)
    if prog in ("pytest", "jest", "vitest", "mocha", "rspec"):
        return "Running tests"
    if prog in ("go",):
        return {"test": "Running Go tests", "build": "Building Go project", "run": "Running Go program"}.get(sub, "Go " + sub)
    if prog in ("make", "cmake", "ninja", "meson", "qmake6", "qmake", "gcc", "g++", "clang", "rustc", "tsc"):
        return "Building" + (" " + sub if prog == "make" and sub else "")
    if prog in ("grep", "rg", "ag", "ack", "egrep"):
        return "Searching files"
    if prog in ("find", "fd", "locate", "ls", "tree", "du", "stat"):
        return "Looking at files"
    if prog in ("cat", "head", "tail", "less", "bat", "wc", "jq", "awk", "cut", "sort", "uniq", "diff", "xxd", "file"):
        return "Reading files"
    if prog == "sed":
        return "Editing files" if any(a.startswith("-i") for a in w) else "Reading files"
    if prog in ("cp", "mv", "rm", "mkdir", "touch", "chmod", "ln", "tee", "install", "rsync"):
        return {"rm": "Deleting files", "rsync": "Syncing files"}.get(prog, "Changing files")
    if prog in ("curl", "wget", "http", "xh"):
        url = next((a for a in w[1:] if "://" in a), "")
        host = re.sub(r"^\w+://([^/:]+).*", r"\1", url) if url else ""
        return "Fetching " + host if host else "Downloading"
    if prog in ("ssh", "scp", "mosh"):
        return "Remote session on " + re.sub(r"^.*@", "", sub) if sub else "Remote session"
    if prog in ("docker", "podman"):
        return "Docker " + sub if sub else "Docker"
    if prog in ("pacman", "yay", "paru", "apt", "dnf", "brew", "pip", "pip3", "uv"):
        return "Installing packages" if sub in ("-S", "install", "add", "sync", "pip") or "-S" in w else prog + " " + sub
    if prog in ("tar", "unzip", "zip", "gzip", "xz", "7z"):
        return "Unpacking files" if prog in ("unzip",) or "-x" in "".join(w[1:2]) else "Packing files"
    if prog in ("systemctl", "journalctl"):
        return "Checking services" if prog == "journalctl" or sub in ("status", "is-active", "list-units") else "Managing services"
    if prog in ("hyprctl", "omarchy", "qs", "quickshell"):
        return prog.capitalize() + (" " + sub if sub else "")
    if prog in ("ps", "pgrep", "top", "btop", "htop", "free", "uptime", "lsof", "ss", "ip", "ping"):
        return "Checking the system"
    if prog in ("ffmpeg", "magick", "convert", "grim"):
        return "Processing media"
    if prog in ("playwright", "chromium", "chrome", "google-chrome", "firefox"):
        return "Driving a browser"
    if prog in ("sqlite3", "psql", "mysql", "redis-cli"):
        return "Querying a database"
    return "Running " + prog


def describe_script(script):
    first_setup = None
    for cmd in split_commands(script[:MAX_CMD]):
        w = main_words(cmd)
        if not w:
            continue
        prog = _base(w[0])
        if prog == "sleep":
            first_setup = first_setup or "Waiting"
            continue
        if _SETUP.match(prog) or prog in ("echo", "printf", "test", "[", "[[", "true", "false", "read"):
            continue
        d = describe_words(w)
        if d:
            return d
    return first_setup or "Shell command"


def describe(args):
    if not args:
        return "Process"
    script = unwrap_shell(args)
    if script is not None:
        return redact(describe_script(script))
    return redact(describe_words(main_words(" ".join(_quote(a) for a in args))) or "Running " + _base(args[0]))


def _quote(a):
    return "'" + a + "'" if (not a or any(c.isspace() for c in a)) and "'" not in a else a


_MCP = re.compile(r"(?i)(?:^|[/@\-_])mcp(?:$|[\-_/.@])|modelcontextprotocol|mcp-server|server-[a-z]+")


def mcp_name(args):
    """If this looks like an MCP server, return a short name for it."""
    head = " ".join(args[:4])[:600]
    if not _MCP.search(head) and "mcp" not in (os.path.basename(args[0]) if args else ""):
        return None
    parts = [seg for a in args[:6] for seg in reversed(a.rstrip("/").split("/"))]
    for b in parts:
        b = re.sub(r"\.(?:js|mjs|cjs|py|ts)$", "", b)
        if re.search(r"(?i)mcp|server-", b):
            b = re.sub(r"(?i)^(?:mcp[-_]server[-_]|server[-_]|mcp[-_])|(?:[-_]mcp(?:[-_]server)?)$", "", b)
            return redact(b or "mcp")[:24]
    return "mcp"


# --------------------------------------------------------------------------
# /proc reading
# --------------------------------------------------------------------------
def read_stat(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    r = raw.rfind(b")")
    comm = raw[raw.find(b"(") + 1:r].decode("utf-8", "replace")
    f = raw[r + 2:].split()
    # f[0]=state f[1]=ppid f[11]=utime f[12]=stime f[19]=starttime f[21]=rss
    return comm, int(f[1]), int(f[11]) + int(f[12]), int(f[19]), int(f[21])


def read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read(MAX_CMD * 2)
    except OSError:
        return []
    return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]


def read_env(pid, keys):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read()
    except OSError:
        return {}
    out = {}
    for item in raw.split(b"\0"):
        k, _, v = item.partition(b"=")
        k = k.decode("ascii", "replace")
        if k in keys:
            out[k] = v.decode("utf-8", "replace")
    return out


def owned(pid):
    try:
        return os.stat(f"/proc/{pid}").st_uid == MY_UID
    except OSError:
        return False


def boot_time():
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("btime"):
                return int(line.split()[1])
    return int(time.time())


BOOT = boot_time()


def pretty_folder(path):
    if path.rstrip("/") == os.path.expanduser("~"):
        return "~"
    name = os.path.basename(path.rstrip("/")) or path
    m = re.match(r"^\d{4}-\d{2}-\d{2}-(.+?)-[0-9a-f]{6,}$", name)   # T3 scratch folders
    if m:
        name = m.group(1).replace("-", " ")
        name = name[:1].upper() + name[1:]
    return name


class Scanner:
    def __init__(self):
        self.prev = {}          # pid -> (start, ticks)
        self.prev_t = None
        self.cmd = {}           # (pid, start) -> args
        self.envc = {}          # (pid, start) -> env subset
        self.desc = {}          # (pid, start) -> description
        self.agent_info = {}    # (pid, start) -> dict(name, host, label, thread)
        self.titles = {}        # thread id -> (title, fetched_at)
        self.done = {}          # agent key -> list of (expires, task dict)
        self.seen_tasks = {}    # agent key -> {task key: task dict}

    def args(self, key):
        a = self.cmd.get(key)
        if a is None:
            a = self.cmd[key] = read_cmdline(key[0])
        return a

    def env(self, key, keys=("CLAUDE_PID", "T3CODE_THREAD_ID", "CODEX_THREAD_ID")):
        e = self.envc.get(key)
        if e is None:
            e = self.envc[key] = read_env(key[0], keys)
        return e

    def thread_title(self, tid):
        cached = self.titles.get(tid)
        now = time.time()
        if cached and now - cached[1] < 60:
            return cached[0]
        title = None
        try:
            con = sqlite3.connect(f"file:{T3_DB}?mode=ro", uri=True, timeout=0.2)
            try:
                for table in ("orchestration_v2_projection_threads", "projection_threads"):
                    try:
                        row = con.execute(f"select title from {table} where thread_id=?", (tid,)).fetchone()
                    except sqlite3.Error:
                        row = None
                    if row and row[0]:
                        title = row[0]
                        break
            finally:
                con.close()
        except sqlite3.Error:
            pass
        self.titles[tid] = (title, now)
        return title

    def agent_name(self, key, comm):
        base = comm.lower()
        if base in AGENTS:
            a = self.args(key)
            joined = " ".join(a[1:4])
            if "--chrome-native-host" in joined or re.search(r"\bmcp\b", joined):
                return None
            return AGENTS[base]
        if comm in LAUNCHERS or comm.startswith("python"):
            a = self.args(key)
            for s in a[1:3]:
                b = os.path.basename(s).lower()
                b = re.sub(r"\.(?:js|mjs|cjs|py)$", "", b)
                if b in AGENTS:
                    return AGENTS[b]
                m = re.search(r"/(?:@[^/]+/)?(gemini-cli|claude-code|codex|opencode|qwen-code|copilot)(?:/|$)", s)
                if m:
                    return {"gemini-cli": "Gemini CLI", "claude-code": "Claude Code", "codex": "Codex",
                            "opencode": "OpenCode", "qwen-code": "Qwen Code", "copilot": "Copilot CLI"}[m.group(1)]
        return None

    def scan(self):
        now = time.time()
        procs = {}
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            st = read_stat(pid)
            if st:
                procs[pid] = st
        children = {}
        for pid, (_, ppid, _, _, _) in procs.items():
            children.setdefault(ppid, []).append(pid)

        dt = (now - self.prev_t) if self.prev_t else 0
        cpu = {}
        for pid, (_, _, ticks, start, _) in procs.items():
            p = self.prev.get(pid)
            if dt > 0 and p and p[0] == start:
                cpu[pid] = max(0.0, (ticks - p[1]) / CLK / dt * 100.0 / NCPU)
            else:
                cpu[pid] = 0.0

        def key(pid):
            return (pid, procs[pid][3])

        # Agents
        agents = {}
        for pid, (comm, _, _, _, _) in procs.items():
            if comm.lower() in AGENTS or comm in LAUNCHERS or comm.startswith("python"):
                if not owned(pid):
                    continue
                n = self.agent_name(key(pid), comm)
                if n:
                    agents[pid] = n

        # Orphans that still carry CLAUDE_PID (backgrounded jobs whose parent shell exited)
        adopted = {}
        live_claude = {pid for pid, n in agents.items() if n == "Claude Code"}
        if live_claude:
            for pid, (comm, ppid, _, _, _) in procs.items():
                if pid in agents or ppid in procs and procs[ppid][0] not in ("systemd", "init"):
                    continue
                if ppid == 0 or pid == 1 or not owned(pid):
                    continue
                cp = self.env(key(pid)).get("CLAUDE_PID", "")
                if cp.isdigit() and int(cp) in live_claude:
                    adopted.setdefault(int(cp), []).append(pid)

        def subtree(root, stop):
            total_cpu, total_rss, stack, n = 0.0, 0, [root], 0
            while stack:
                p = stack.pop()
                if p not in procs:
                    continue
                n += 1
                total_cpu += cpu.get(p, 0.0)
                total_rss += procs[p][4] * PAGE
                for c in children.get(p, ()):
                    if c not in stop:
                        stack.append(c)
            return total_cpu, total_rss, n

        out_agents = []
        stop = set(agents)
        live_keys = set()
        for apid, aname in sorted(agents.items()):
            akey = key(apid)
            live_keys.add(akey)
            info = self.agent_info.get(akey)
            if info is None:
                host, p, hops = "", procs[apid][1], 0
                while p in procs and hops < 12 and not host:
                    c = procs[p][0]
                    for prefix, label in HOSTS:
                        if c.startswith(prefix):
                            host = label
                            break
                    p, hops = procs[p][1], hops + 1
                try:
                    cwd = os.readlink(f"/proc/{apid}/cwd")
                except OSError:
                    cwd = ""
                info = self.agent_info[akey] = {
                    "host": host or "Terminal",
                    "folder": pretty_folder(cwd) if cwd else "",
                    "thread": self.env(akey).get("T3CODE_THREAD_ID", ""),
                }
            label = self.thread_title(info["thread"]) if info["thread"] else None
            label = redact(label or info["folder"] or "")

            a_cpu, a_rss, _ = subtree(apid, stop - {apid})
            tasks, mcps = [], []
            seen = self.seen_tasks.setdefault(akey, {})
            current = set()
            for c in children.get(apid, []) + adopted.get(apid, []):
                if c in agents or c not in procs:
                    continue
                ckey = key(c)
                args = self.args(ckey)
                if args and args[0].endswith("sh") and "trap '' TERM" in " ".join(args[:3]):
                    continue                          # T3's watchdog shell
                if ckey not in self.desc:
                    m = mcp_name(args)
                    self.desc[ckey] = ("mcp", m) if m else ("task", describe(args))
                kind, text = self.desc[ckey]
                if kind == "mcp":
                    mcps.append(text)
                    continue
                t_cpu, t_rss, t_n = subtree(c, stop)
                if c in adopted.get(apid, []):
                    a_cpu += t_cpu
                    a_rss += t_rss
                task = {
                    "id": f"{c}-{procs[c][3]}",
                    "text": text,
                    "started": int(BOOT + procs[c][3] / CLK),
                    "cpu": round(t_cpu, 1),
                    "mem": t_rss // (1024 * 1024),
                    "procs": t_n,
                }
                tasks.append(task)
                current.add(task["id"])
                seen[task["id"]] = task

            # finished tasks linger for DONE_HOLD seconds
            held = [d for d in self.done.get(akey, []) if d[0] > now]
            for tid in list(seen):
                if tid not in current:
                    t = dict(seen.pop(tid))
                    t.update(cpu=0, mem=0, done=True, ended=int(now))
                    held.append((now + DONE_HOLD, t))
            self.done[akey] = held

            tasks.sort(key=lambda t: (-t["cpu"], -t["started"]))
            shown = tasks[:MAX_TASKS_PER_AGENT]
            shown += [d[1] for d in sorted(held, key=lambda d: -d[0])][: max(0, MAX_TASKS_PER_AGENT - len(shown))]
            out_agents.append({
                "id": f"{apid}-{procs[apid][3]}",
                "name": aname,
                "host": info["host"],
                "label": label,
                "started": int(BOOT + procs[apid][3] / CLK),
                "cpu": round(a_cpu, 1),
                "mem": a_rss // (1024 * 1024),
                "tasks": shown,
                "hidden": max(0, len(tasks) - MAX_TASKS_PER_AGENT),
                "mcp": sorted(set(mcps)),
            })

        # Forget caches for processes that are gone
        alive = {key(p) for p in procs}
        for cache in (self.cmd, self.envc, self.desc, self.agent_info):
            for k in [k for k in cache if k not in alive]:
                del cache[k]
        for k in [k for k in self.seen_tasks if k not in live_keys]:
            del self.seen_tasks[k]
            self.done.pop(k, None)

        self.prev = {pid: (st[3], st[2]) for pid, st in procs.items()}
        self.prev_t = now
        out_agents.sort(key=lambda a: (-a["cpu"], a["name"], a["started"]))
        return {
            "agents": out_agents,
            "cpu": round(sum(a["cpu"] for a in out_agents), 1),
            "mem": sum(a["mem"] for a in out_agents),
            "busy": sum(1 for a in out_agents for t in a["tasks"] if not t.get("done")),
            "ncpu": NCPU,
        }


def main():
    if "--once" in sys.argv:
        s = Scanner()
        s.scan()
        time.sleep(1.0)
        print(json.dumps(s.scan(), indent=2))
        return
    try:
        os.nice(10)
    except OSError:
        pass
    s = Scanner()
    interval = SLOW
    last = None
    while True:
        snap = s.scan()
        line = json.dumps(snap, separators=(",", ":"))
        if line != last:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            last = line
        ready, _, _ = select.select([sys.stdin], [], [], interval)
        if ready:
            msg = sys.stdin.readline()
            if not msg:
                return          # the shell went away
            msg = msg.strip()
            if msg == "open":
                interval = FAST
            elif msg == "closed":
                interval = SLOW


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, BrokenPipeError):
        pass

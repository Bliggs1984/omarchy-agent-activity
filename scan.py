#!/usr/bin/env python3
"""Agent Top scanner for the Omarchy bar.

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
    "kimi-code": "Kimi Code",     # sets its process title, so comm and cmdline are just this
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


def is_launcher(comm):
    # Node 23-25 name the main thread "MainThread", Node 26 "node-MainThread"
    return comm in LAUNCHERS or comm.startswith("python") or comm.endswith("MainThread")


def fold_agents(agents, parent):
    """Agents started directly by an agent of the same name, mapped to the top
    of that chain. Gemini and Qwen relaunch themselves, npm installs wrap a
    native binary in a node script, OpenCode starts its own server: one session,
    so one row. Only a direct parent counts: an agent that another session
    started through a shell is a session of its own."""
    out = {}
    for pid, name in agents.items():
        root, hops = pid, 0
        while agents.get(parent.get(root)) == name and hops < 8:
            root, hops = parent[root], hops + 1
        if root != pid:
            out[pid] = root
    return out


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
# A name starts only where no name character precedes it. With a plain \b each
# position inside "a-a-a-..." was a new start, which made matching quadratic.
_NB = r"(?<![A-Za-z0-9_\-])"
_REDACTIONS = [
    # NAME=value, --name=value, "name": "value", name: value. A plain space after
    # an ordinary word ("Remote session on host") is not a separator.
    re.compile(r"(?i)" + _NB + "(" + _SECRET_NAME + r"[\"']?\s*[=:]\s*[\"']?)([^\s\"'&;|]+)"),
    # Authorization headers
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)?\s*)(\S+)"),
    # user:password@ in URLs
    re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)"),
    # --name value, -name value (the value may not itself be an option)
    re.compile(r"(?i)" + _NB + r"(-{1,2}" + _SECRET_NAME + r"\s+[\"']?)([^\s\"'&;|\-][^\s\"'&;|]*)"),
]
_TOKEN_SHAPES = re.compile(
    r"\b(?:sk-[A-Za-z0-9_\-]{12,}|sk-ant-[A-Za-z0-9_\-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"
    r"|glpat-[A-Za-z0-9_\-]{16,}|hf_[A-Za-z0-9]{20,})\b")


def redact(text):
    """Mask secrets. Cuts to 256 characters first; callers cut to display length
    afterwards (cutting short before masking could leave a key's prefix bare)."""
    if not text:
        return text
    text = text[:256]
    text = _TOKEN_SHAPES.sub("•••", text)
    text = _REDACTIONS[1].sub(lambda m: m.group(1) + "•••", text)   # headers before the generic rule
    text = _REDACTIONS[0].sub(lambda m: m.group(1) + "•••", text)
    text = _REDACTIONS[3].sub(lambda m: m.group(1) + "•••", text)
    text = _REDACTIONS[2].sub(lambda m: m.group(1) + "•••" + m.group(3), text)
    return text


# --------------------------------------------------------------------------
# Plain-English descriptions of commands
# --------------------------------------------------------------------------
_CLAUDE_EVAL = re.compile(r"\beval '((?:[^']|'\"'\"')*)'")
_SKIP_WORDS = {"sudo", "env", "nice", "ionice", "time", "command", "exec", "builtin", "nohup", "stdbuf"}
_WRAPPERS = _SKIP_WORDS | {"timeout"}       # programs whose job is to run another program
_SETUP = re.compile(r"^(?:cd|export|source|\.|set|shopt|unset|unalias|trap|true|:|local|declare|ulimit|umask|pushd|popd|eval)$")


def unwrap_shell(args, depth=0):
    """Return the script a shell was asked to run, or None."""
    if not args or depth > 3:
        return None
    prog = os.path.basename(args[0])
    if prog not in SHELLS:
        return None
    # Options come first: -c alone or in a bundle (-ec, -ilc), -o/-O with a value
    # (also at the end of a bundle: -euo pipefail), long options (--norc).
    # The script is the first argument after them.
    i, c = 1, False
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a[:1] in "-+" and a[1:].isalpha():
            c = c or a[0] == "-" and "c" in a
            i += 2 if a[-1] in "oO" else 1
            continue
        if a.startswith("--"):
            i += 1
            continue
        break
    if not c or i >= len(args):
        return None
    script = args[i][:MAX_CMD]
    m = _CLAUDE_EVAL.search(script)          # Claude Code's Bash tool
    if m:
        return m.group(1).replace("'\"'\"'", "'")
    return script


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


# Display guard: an argument is pasted into a summary only if it has a safe
# shape; otherwise it is dropped and the generic label is used.
_SUB_OK = re.compile(r"[a-z][a-z0-9:._-]{0,24}")                    # subcommands
_NAME_OK = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9._:@+-]{0,39}")       # script, program, package names
_HOST_OK = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?")


def _sub(s, before=" "):
    return before + s if _SUB_OK.fullmatch(s) else ""


def _name(s):
    b = _base(s) if s else ""
    return b if _NAME_OK.fullmatch(b) else ""


def _host(s):
    """Host of a URL or of ssh's [user@]host[:path], or "" if it looks odd.
    By hand: urllib.parse would add almost 1 MB to the scanner."""
    if "://" in s:
        s = re.split(r"[/?#]", s.split("://", 1)[1], maxsplit=1)[0]
    s = s.rpartition("@")[2].partition(":")[0].lower()
    return s if _HOST_OK.fullmatch(s) else ""


def proc_label(text, prog):
    """The program's name for the row, or "" if the summary already says it."""
    name = _name(prog)
    stem = re.sub(r"[\d.]+$", "", name).lower() or name.lower()
    return "" if not name or stem in text.lower() else redact(name)[:24]


def _running(s, generic):
    n = _name(s)
    return "Running " + n if n else generic


def describe_words(w):
    if not w:
        return None
    prog = _base(w[0])
    sub = _arg(w)
    if prog in SHELLS:
        inner = unwrap_shell(w)
        if inner:
            return describe_script(inner)
        return _running(sub, "Shell")
    if _SETUP.match(prog) or prog in ("echo", "printf", "sleep", "wait", "test", "[", "[[", "read"):
        return {"sleep": "Waiting", "wait": "Waiting for jobs"}.get(prog)
    if prog == "git":
        return "Git" + _sub(sub)
    if prog == "gh":
        return "GitHub" + "".join(_sub(a) for a in w[1:3] if not a.startswith("-"))
    if prog == "cargo":
        return {"test": "Running Rust tests", "build": "Building Rust project", "run": "Running Rust program",
                "check": "Checking Rust code", "clippy": "Linting Rust code", "fmt": "Formatting Rust code"}.get(sub, "Cargo" + _sub(sub))
    if prog in ("npm", "pnpm", "yarn", "bun"):
        if sub in ("run", "run-script"):
            n = _name(_arg(w, 2))
            return prog + " run" + (" " + n if n else "")
        if sub in ("test", "t"):
            return "Running JS tests"
        if sub in ("install", "i", "add", "ci"):
            return "Installing packages"
        if sub in ("x", "exec", "dlx") or prog == "bun" and sub.endswith((".ts", ".js")):
            return _running(_arg(w, 2) or sub, prog)
        return prog + _sub(sub)
    if prog in ("npx", "bunx", "uvx", "pnpx"):
        return _running(sub, prog)
    if prog.startswith("python") or prog in ("node", "deno", "ruby", "perl", "php"):
        generic = {"node": "Node script", "deno": "Deno script"}.get(prog, "Python script" if prog.startswith("python") else prog + " script")
        if "-m" in w:
            mod = w[w.index("-m") + 1] if w.index("-m") + 1 < len(w) else ""
            return {"pytest": "Running Python tests", "pip": "Installing packages", "http.server": "Serving files"}.get(mod) or _running(mod, generic)
        if "-c" in w or "-e" in w or "--eval" in w or not sub or sub.startswith("$"):
            return generic
        return _running(sub, generic)
    if prog in ("pytest", "jest", "vitest", "mocha", "rspec"):
        return "Running tests"
    if prog in ("go",):
        return {"test": "Running Go tests", "build": "Building Go project", "run": "Running Go program"}.get(sub, "Go" + _sub(sub))
    if prog in ("make", "cmake", "ninja", "meson", "qmake6", "qmake", "gcc", "g++", "clang", "rustc", "tsc"):
        n = _name(sub) if prog == "make" else ""
        return "Building" + (" " + n if n else "")
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
        host = _host(next((a for a in w[1:] if "://" in a), ""))
        return "Fetching " + host if host else "Downloading"
    if prog in ("ssh", "scp", "mosh"):
        host = _host(sub)
        return "Remote session on " + host if host else "Remote session"
    if prog in ("docker", "podman"):
        return "Docker" + _sub(sub)
    if prog in ("pacman", "yay", "paru", "apt", "dnf", "brew", "pip", "pip3", "uv"):
        return "Installing packages" if sub in ("-S", "install", "add", "sync", "pip") or "-S" in w else prog + _sub(sub)
    if prog in ("tar", "unzip", "zip", "gzip", "xz", "7z"):
        return "Unpacking files" if prog in ("unzip",) or "-x" in "".join(w[1:2]) else "Packing files"
    if prog in ("systemctl", "journalctl"):
        return "Checking services" if prog == "journalctl" or sub in ("status", "is-active", "list-units") else "Managing services"
    if prog in ("hyprctl", "omarchy", "qs", "quickshell"):
        return prog.capitalize() + _sub(sub)
    if prog in ("ps", "pgrep", "top", "btop", "htop", "free", "uptime", "lsof", "ss", "ip", "ping"):
        return "Checking the system"
    if prog in ("ffmpeg", "magick", "convert", "grim"):
        return "Processing media"
    if prog in ("playwright", "chromium", "chrome", "google-chrome", "firefox"):
        return "Driving a browser"
    if prog in ("sqlite3", "psql", "mysql", "redis-cli"):
        return "Querying a database"
    return _running(prog, "Running a program")


def real_commands(script):
    """main_words of each command in a script, skipping setup like cd/export/echo."""
    for cmd in split_commands(script[:MAX_CMD]):
        w = main_words(cmd)
        if w and not (_SETUP.match(_base(w[0])) or _base(w[0]) in ("echo", "printf", "test", "[", "[[", "true", "false", "read")):
            yield w


def describe_script(script):
    first_setup = None
    for w in real_commands(script):
        if _base(w[0]) == "sleep":
            first_setup = first_setup or "Waiting"
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
        return redact(describe_script(script))[:80]
    d = describe_words(main_words(" ".join(_quote(a) for a in args))) or _running(args[0], "Running a program")
    return redact(d)[:80]


def _quote(a):
    return "'" + a + "'" if (not a or any(c.isspace() for c in a)) and "'" not in a else a


# "mcp" as a whole word inside a path segment, or the official package scope
_MCP = re.compile(r"(?i)(?:^|[/@\-_.])mcp(?:$|[/@\-_.])|modelcontextprotocol")
_MCP_SUBS = ("mcp", "mcp-server", "start-mcp-server")
_DOCKER_VALUE = ("-e", "--env", "-v", "--volume", "--name", "-p", "--network")
_MCP_NAME_OK = re.compile(r"[A-Za-z0-9._@-]{1,24}")


def _first_plain(w, i):
    """Index of the first word at or after i that is not an option, or None."""
    return next((j for j in range(i, len(w)) if not w[j].startswith("-")), None)


def _script_at(w):
    """Index of the script a node/bun/python launcher runs: the first argument
    that is not an option, or python's -m module (python -W ignore -m aider)."""
    i = _first_plain(w, 1)
    if "-m" in w[1:-1] and _base(w[0]).startswith("python"):
        m = w.index("-m", 1)
        if i is None or m < i or not any("/" in a or a.endswith(".py") for a in w[1:m]):
            return m + 1
    return i


def mcp_name(args):
    """If this looks like an MCP server, return a short name for it.

    Only the program and, for launchers (npx, docker run, node, ...), the
    package or script it runs are looked at, never the rest of the command."""
    script = unwrap_shell(args)
    if script is None:
        w = args
    else:
        w = next((w for w in real_commands(script) if _base(w[0]) != "sleep"), None)
    if not w:
        return None
    prog = _base(w[0])
    pkg = None
    if prog in ("npx", "bunx", "uvx", "pnpx"):
        pkg = _first_plain(w, 1)
    elif prog in ("docker", "podman") and w[1:2] == ["run"]:
        i = 2
        while i < len(w) and w[i].startswith("-"):
            i += 2 if w[i] in _DOCKER_VALUE else 1
        pkg = i if i < len(w) else None
    elif prog in ("npm", "pnpm", "yarn", "bun", "uv") and w[1:2] and w[1] in ("exec", "x", "dlx", "run"):
        pkg = _first_plain(w, 2)
    elif prog == "uv" and w[1:3] == ["tool", "run"]:
        pkg = _first_plain(w, 3)
    elif script is None and (prog in ("node", "bun", "deno") or prog.startswith("python")):
        # A direct child of the agent; a script run through the agent's shell is a task.
        pkg = _script_at(w)
    named = w[pkg] if pkg is not None else w[0]
    # Through a shell only the program's name counts, not the folder it sits in
    # (/home/u/my-mcp/node_modules/.bin/jest is a test run, not a server).
    cand = [w[0] if script is None else prog] + ([named] if pkg is not None else [])
    hit = next((c for c in cand if _MCP.search(c)), None)
    if hit is not None:
        segs = reversed(hit.rstrip("/").split("/"))
        name = "mcp"
        for b in segs:
            b = re.sub(r"\.(?:js|mjs|cjs|py|ts)$", "", b)
            if re.search(r"(?i)mcp|server-", b):
                name = re.sub(r"(?i)^(?:mcp[-_]server[-_]|server[-_]|mcp[-_])|(?:[-_]mcp(?:[-_]server)?)$", "", b) or "mcp"
                if name.lower() == "mcp":           # @playwright/mcp: use the scope
                    scope = next(segs, "")
                    name = scope[1:] if scope.startswith("@") and len(scope) > 1 else "mcp"
                break
    elif script is None and any(a in _MCP_SUBS for a in w[1:4]):
        # "serena start-mcp-server", "codex mcp-server". Direct children only:
        # in a shell command these are usually arguments ("grep -rn mcp-server").
        name = re.sub(r"\.(?:js|mjs|cjs|py|ts)$", "", _base(named))
    else:
        return None
    name = redact(name)[:24]
    return name if _MCP_NAME_OK.fullmatch(name) else "mcp"


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
        self.names = {}         # ((pid, start), comm) -> agent name or None, so each process is judged once
        self.titles = {}        # thread id -> (title, fetched_at)
        self.done = {}          # agent key -> list of (expires, task dict)
        self.seen_tasks = {}    # agent key -> {task key: task dict}

    def args(self, key):
        a = self.cmd.get(key)
        if a is None:
            a = self.cmd[key] = read_cmdline(key[0])
        return a

    def env(self, key, keys=("CLAUDE_PID", "T3CODE_THREAD_ID")):
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

    @staticmethod
    def helper(a, at):
        # Helper modes of an agent binary (MCP server, browser bridge), not a session.
        # Only the subcommand slot counts: "--mcp-config x" or "-p 'add an mcp tool'" are sessions.
        # "codex app-server daemon ..." is the bookkeeping half of Codex's background service.
        return ("--chrome-native-host" in a or a[1:3] == ["app-server", "daemon"]
                or any(i < len(a) and a[i] in ("mcp", "mcp-server") for i in at))

    def current(self, pid, procs, children, agents):
        """The process a task is running right now: follow shells and wrappers
        (sudo, timeout, ...) down to the command they are waiting on. A script
        is summarised from its first command, which may have finished long ago."""
        for _ in range(6):
            a = self.args((pid, procs[pid][3]))
            kids = [k for k in children.get(pid, ()) if k not in agents]
            if not kids or not a or not (unwrap_shell(a) is not None or _base(a[0]) in _WRAPPERS):
                break
            pid = min(kids, key=lambda k: (procs[k][3], k))     # oldest: the first command of a pipeline
        return pid

    def agent_name(self, key, comm):
        base = comm.lower()
        if base in AGENTS:
            a = self.args(key)
            return None if self.helper(a, (1,)) else AGENTS[base]
        if is_launcher(comm):
            a = self.args(key)
            if not a:
                return None
            # Candidates: the program itself (cursor-agent, copilot's native binary)
            # and the script it runs. Later arguments are the agent's own options.
            s = _script_at(a)
            for j in (0, s):
                if j is None:
                    continue
                b = re.sub(r"\.(?:js|mjs|cjs|py)$", "", os.path.basename(a[j]).lower())
                name = AGENTS.get(b)
                if not name:
                    m = re.search(r"/(?:@[^/]+/)?(gemini-cli|claude-code|codex|opencode|qwen-code|copilot)(?:/|$)", a[j])
                    name = m and {"gemini-cli": "Gemini CLI", "claude-code": "Claude Code", "codex": "Codex",
                                  "opencode": "OpenCode", "qwen-code": "Qwen Code", "copilot": "Copilot CLI"}[m.group(1)]
                if name:
                    # the subcommand follows the script ([cursor-agent, --flag, index.js, mcp])
                    at = (1,) if s is None else (s, s + 1) if j == 0 else (s + 1,)
                    return None if self.helper(a, at) else name
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
            if comm.lower() in AGENTS or is_launcher(comm):
                nk = (key(pid), comm)       # comm is in the key: it changes when a process execs or renames itself
                n = self.names.get(nk, 0)
                if n == 0:
                    n = self.names[nk] = self.agent_name(nk[0], comm) if owned(pid) else None
                if n:
                    agents[pid] = n

        # Orphans that still carry CLAUDE_PID (backgrounded jobs whose parent shell exited)
        adopted = {}
        live_claude = {pid for pid, n in agents.items() if n == "Claude Code"}
        if live_claude:
            for pid, (comm, ppid, _, _, _) in procs.items():
                if pid in agents or comm.lower() in AGENTS or ppid in procs and procs[ppid][0] not in ("systemd", "init"):
                    continue                          # agents, their helpers and daemons are not jobs
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

        # One row per session (see fold_agents). A folded agent's processes, tasks
        # and orphans count under the agent at the top of its chain.
        folded = fold_agents(agents, {p: procs[p][1] for p in agents})
        members = {}
        for c, r in folded.items():
            members.setdefault(r, []).append(c)

        out_agents = []
        stop = set(agents) - set(folded)
        live_keys = set()
        for apid, aname in sorted(agents.items()):
            if apid in folded:
                continue
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
            label = redact(label or info["folder"] or "")[:80]

            a_cpu, a_rss, _ = subtree(apid, stop - {apid})
            tasks, mcps = [], []
            seen = self.seen_tasks.setdefault(akey, {})
            current = set()
            own = [apid] + members.get(apid, [])
            orphans = {c for m in own for c in adopted.get(m, ())}
            for c in [c for m in own for c in children.get(m, ())] + sorted(orphans):
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
                cur = self.current(c, procs, children, agents)
                cargs = self.args(key(cur)) or [procs[cur][0]]
                if cur != c:
                    if key(cur) not in self.desc:
                        self.desc[key(cur)] = ("task", describe(cargs))
                    text = self.desc[key(cur)][1]
                # a shell between two commands has no program to name
                prog = "" if unwrap_shell(cargs) is not None else proc_label(text, cargs[0])
                t_cpu, t_rss, t_n = subtree(c, stop)
                if c in orphans:
                    a_cpu += t_cpu
                    a_rss += t_rss
                task = {
                    "id": f"{c}-{procs[c][3]}",
                    "text": text,
                    "proc": prog,
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
            if not tasks and not held and "--managed-daemon" in self.args(akey):
                continue        # Codex's background service: a row only while it runs something

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
        for k in [k for k in self.names if k[0] not in alive]:
            del self.names[k]
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
    errors = set()
    while True:
        try:
            snap = s.scan()
        except Exception as e:      # keep going; an empty snapshot clears stale rows
            err = f"{type(e).__name__}: {e}"[:300]
            if err not in errors and len(errors) < 100:
                errors.add(err)
                sys.stderr.write("agent-activity: scan failed: " + err + "\n")
                sys.stderr.flush()
            snap = {"agents": [], "cpu": 0, "mem": 0, "busy": 0, "ncpu": NCPU}
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

"""Run with: python3 -I tests/test_scan.py  (from the plugin folder)"""
import sys
sys.dont_write_bytecode = True          # no __pycache__ next to scan.py
import importlib.util
import io
import os
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("scan", os.path.join(HERE, "..", "scan.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

CLAUDE_WRAP = ("source /home/u/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && "
               "shopt -u extglob 2>/dev/null || true && eval '{}' && pwd -P >| /tmp/claude-abcd-cwd")
# The shape Claude Code uses today: alias cleanup, and stdin from /dev/null after the eval
CLAUDE_WRAP2 = ("source /home/u/.claude/shell-snapshots/snapshot-bash-1794525041951-se883j.sh 2>/dev/null || true && "
                "shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'which'; \\builtin unset -f -- 'which'; } "
                ">/dev/null 2>&1 || true && eval '{}' < /dev/null && pwd -P >| /tmp/claude-8ca7-cwd")


def claude(cmd, wrap=CLAUDE_WRAP):
    return ["/usr/bin/bash", "-c", wrap.replace("{}", cmd.replace("'", "'\"'\"'"))]


def quick(fn, *args):
    t = time.perf_counter()
    fn(*args)
    return time.perf_counter() - t


class Describe(unittest.TestCase):
    def test_claude_bash_tool(self):
        self.assertEqual(scan.describe(claude("cd /x && cargo test --release")), "Running Rust tests")
        self.assertEqual(scan.describe(claude("grep -rn 'foo bar' src | head")), "Searching files")

    def test_skips_setup_and_sleep(self):
        self.assertEqual(scan.describe(["sh", "-c", "export A=1; sleep 2; npm run build"]), "npm run build")
        self.assertEqual(scan.describe(["sh", "-c", "sleep 30"]), "Waiting")

    def test_plain_programs(self):
        self.assertEqual(scan.describe(["git", "status"]), "Git status")
        self.assertEqual(scan.describe(["python3", "tools/build.py"]), "Running build.py")
        self.assertEqual(scan.describe(["python3", "-m", "pytest", "-q"]), "Running Python tests")
        self.assertEqual(scan.describe(["sed", "-i", "s/a/b/", "f"]), "Editing files")
        self.assertEqual(scan.describe(["weirdtool", "--x"]), "Running weirdtool")

    def test_prefixes(self):
        self.assertEqual(scan.describe(["sh", "-c", "FOO=1 timeout 5 sudo -E pacman -S x"]), "Installing packages")

    def test_loops_and_conditionals(self):
        self.assertEqual(scan.describe(["bash", "-c", "while :; do grep -r TODO src; done"]), "Searching files")
        self.assertEqual(scan.describe(["bash", "-c", "for f in *.py; do python3 $f; done"]), "Python script")
        self.assertEqual(scan.describe(["bash", "-c", "if [ -f x ]; then make; fi"]), "Building")

    def test_unknown_shell(self):
        self.assertEqual(scan.describe(["bash", "-c", "& ; |"]), "Shell command")


class Redact(unittest.TestCase):
    def test_secrets_masked(self):
        cases = [
            "API_KEY=abc123 run", "--password hunter2", "--token=abc", '{"token":"abc"}',
            "password: abc", "Authorization: Bearer abc123", "https://user:pw@host/x",
            "sk-ant-abcdefghijklmnop1234", "ghp_" + "a" * 36,
        ]
        for c in cases:
            out = scan.redact(c)
            self.assertIn("•••", out, c)
            for s in ("abc123", "hunter2", '"abc"', ": abc", "=abc", "pw@", "aaaaaaaaaa", "abcdefghijklmnop"):
                if s in c:
                    self.assertNotIn(s, out, c)

    def test_descriptions_masked(self):
        self.assertNotIn("abcdefghijklmnopqrst", scan.describe(["curl", "https://x.io/?k=sk-abcdefghijklmnopqrst"]))
        self.assertNotIn("secretpw", scan.describe(["ssh", "u:secretpw@host"]) + scan.redact("https://u:secretpw@h"))

    def test_fast_on_hostile_input(self):
        t = time.time()
        scan.describe(["bash", "-c", ("bash -c '" * 50) + "x" * 20000])
        scan.redact("password=" + "a" * 50000 + " token " * 2000)
        self.assertLess(time.time() - t, 0.5)


class Mcp(unittest.TestCase):
    def test_names(self):
        self.assertEqual(scan.mcp_name(["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]), "filesystem")
        self.assertEqual(scan.mcp_name(["node", "/x/chrome-devtools-mcp/index.js"]), "chrome-devtools")
        self.assertIsNone(scan.mcp_name(["bash", "-c", "echo mcp is great"]))


class Folder(unittest.TestCase):
    def test_t3_scratch(self):
        self.assertEqual(scan.pretty_folder("/h/.t3/scratch/2026-11-12-go-through-my-threads-5af6a42d"), "Go through my threads")


class Live(unittest.TestCase):
    def test_scan_runs(self):
        s = scan.Scanner()
        s.scan()
        snap = s.scan()
        self.assertIn("agents", snap)


def agent(comm, argv):
    s = scan.Scanner()
    s.cmd[(1, 1)] = argv
    return s.agent_name((1, 1), comm)


class Agents(unittest.TestCase):
    def test_launchers(self):
        for comm in ("node", "MainThread", "node-MainThread", "python3", "python3.13", "bun"):
            self.assertTrue(scan.is_launcher(comm), comm)
        for comm in ("bash", "Thread", "nodejs-helper"):
            self.assertFalse(scan.is_launcher(comm), comm)

    def test_recognised(self):
        cases = [
            ("node-MainThread", ["node", "/usr/bin/gemini"], "Gemini CLI"),
            ("node", ["/usr/bin/node", "--no-warnings=DEP0040", "--max-old-space-size=7936", "/usr/bin/gemini"], "Gemini CLI"),
            ("MainThread", ["/home/u/.local/bin/cursor-agent", "--use-system-ca",
                            "/home/u/.local/share/cursor-agent/versions/2026.11.11-b912975/index.js"], "Cursor Agent"),
            ("kimi-code", ["kimi-code"], "Kimi Code"),
            ("python3", ["/home/u/.local/share/uv/tools/aider-chat/bin/python", "/home/u/.local/bin/aider", "--model", "x"], "Aider"),
            ("python3", ["python3", "-W", "ignore", "-m", "aider"], "Aider"),
            ("node", ["node", "/x/lib/node_modules/@google/gemini-cli/dist/index.js"], "Gemini CLI"),
            ("MainThread", ["/x/node_modules/@github/copilot-linux-x64/copilot"], "Copilot CLI"),
            ("claude", ["claude", "--resume", "x"], "Claude Code"),
        ]
        for comm, argv, want in cases:
            self.assertEqual(agent(comm, argv), want, argv)

    def test_not_recognised(self):
        for comm, argv in [("node", ["node", "app.js", "--profile", "claude"]), ("node", ["node", "app.js", "codex"]),
                           ("python3", ["python3", "/x/aider", "-m", "codex"]), ("node", []),
                           ("node-MainThread", ["node", "server.js"])]:
            self.assertNotIn(agent(comm, argv), ("Claude Code", "Codex"), argv)
        self.assertIsNone(agent("node", ["node", "app.js", "codex"]))

    def test_helper_modes(self):
        visible = [["claude", "--mcp-config", "mcp.json"], ["claude", "--strict-mcp-config", "--mcp-config", "x"],
                   ["claude", "-p", "add an mcp tool to the server"], ["codex", "app-server"]]
        hidden = [["claude", "mcp", "serve"], ["codex", "mcp-server"], ["/x/claude", "--chrome-native-host"],
                  ["claude", "--resume", "x", "--verbose", "--chrome-native-host"]]
        for argv in visible:
            self.assertIsNotNone(agent(os.path.basename(argv[0]), argv), argv)
        for argv in hidden:
            self.assertIsNone(agent(os.path.basename(argv[0]), argv), argv)
        # launcher branch: the subcommand slot is after the script
        self.assertIsNone(agent("node-MainThread", ["node", "/usr/bin/gemini", "mcp"]))
        self.assertIsNone(agent("MainThread", ["/h/cursor-agent", "--use-system-ca", "/h/index.js", "mcp"]))
        self.assertEqual(agent("node-MainThread", ["node", "/usr/bin/gemini", "--mcp-config", "x"]), "Gemini CLI")


class McpNames(unittest.TestCase):
    def test_servers(self):
        cases = [
            (["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"], "filesystem"),
            (["node", "/x/chrome-devtools-mcp/index.js"], "chrome-devtools"),
            (["uvx", "mcp-server-git", "--repository", "/x"], "git"),
            (["npx", "-y", "mcp-remote", "https://mcp.example.com/sse?api_key=SECRET"], "remote"),
            (["npx", "-y", "@upstash/context7-mcp", "--api-key", "k"], "context7"),
            (["docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"], "github"),
            (["docker", "run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server"], "github"),
            (["sh", "-c", "npx -y foo-mcp"], "foo"),
            (["/usr/bin/python3", "/home/u/.local/bin/serena", "start-mcp-server"], "serena"),
            (["node", "/x/node_modules/@playwright/mcp/cli.js"], "playwright"),
            (["codex", "mcp-server"], "codex"),
            (["node", "/srv/mcp-server-" + "a" * 60], "a" * 24),
            (["/x/github-mcp-server", "stdio"], "github"),
        ]
        for argv, want in cases:
            self.assertEqual(scan.mcp_name(argv), want, argv)

    def test_not_servers(self):
        shell = ["cd /home/u/projects/my-mcp/src && cargo test", "grep -rn mcp-server src/", "cat docs/mcp/readme.md",
                 "cat docs/mcp.md", "pytest tests/test_mcp.py", "python3 tests/test_mcp.py", "node server-dev.js",
                 "npm run server-dev", "npm run start-server-prod", "git log -- packages/mcp/", "ls ~/.config/mcp/"]
        for cmd in shell:
            for wrap in (CLAUDE_WRAP, CLAUDE_WRAP2):
                self.assertIsNone(scan.mcp_name(claude(cmd, wrap)), cmd)
        for argv in (["node", "server-dev.js"], ["python3", "http-server-thing.py"], ["node", "/srv/app/server-side/render.js"],
                     ["bash", "-c", "echo mcp is great"], [], ["bash", "-c", "cd /x"]):
            self.assertIsNone(scan.mcp_name(argv), argv)

    def test_names_are_clean(self):
        for argv in (["npx", "-y", "@x/evil mcp 'quote'"], ["node", "/x/a;b-mcp/i.js"], ["/x/my\"thing-mcp"],
                     ["npx", "-y", "token=hunter2-mcp"], claude("cd ~/my-mcp && ./my-mcp-tool --key hunter2")):
            name = scan.mcp_name(argv)
            if name is not None:
                self.assertRegex(name, r"^[A-Za-z0-9._@-]{1,24}$", argv)
                self.assertNotIn("hunter2", name)


class Masking(unittest.TestCase):
    def test_more_masked(self):
        for c, secret in [("Running run --pass hunter2", "hunter2"), ("-token abc", "abc"), ("MY_SECRET = abc", "abc"),
                          ("--api-key 'k3y'", "k3y"), ("x " * 200 + "password=hunter2", "hunter2")]:
            out = scan.redact(c)
            self.assertNotIn(secret, out, c)

    def test_ordinary_words_kept(self):
        for c in ("Remote session on host", "GitHub auth status", "GitHub secret set", "Fix password reset flow",
                  "Session notes for Monday", "Auth token refresh bug", "Bypass cache in tests", "Compass heading widget",
                  "Author page redesign", "Passing tests on CI", "Tokenizer speedup", "Credentials page copy",
                  "--token --verbose"):
            self.assertEqual(scan.redact(c), c)

    def test_cut_before_mask(self):
        self.assertEqual(len(scan.redact("x" * 1000)), 256)
        self.assertLessEqual(len(scan.describe(["bash", "-c", "npm run " + "b" * 300])), 80)

    def test_speed(self):
        cases = [(scan.redact, "a-" * 8000), (scan.redact, "-a" * 8000), (scan.redact, "-token" * 3000),
                 (scan.describe, ["bash", "-c", "npx " + "a-" * 2000]), (scan.describe, ["python3", "x/" + "a-" * 2000 + ".py"]),
                 (scan.mcp_name, ["node", "/srv/mcp-server-" + "a-" * 2000]), (scan.describe, ["tool", "a-" * 3000]),
                 (scan.mcp_name, ["node", "mcp-" + "a-" * 3000])]
        for fn, arg in cases:
            self.assertLess(quick(fn, arg), 0.05, (fn.__name__, str(arg)[:30]))


class Shells(unittest.TestCase):
    def test_unwrap(self):
        cases = [
            (["sh", "-ec", "npm test"], "npm test"), (["bash", "-euc", "x"], "x"), (["zsh", "-ilc", "x"], "x"),
            (["bash", "-xc", "x"], "x"), (["bash", "-c", "-l", "x"], "x"), (["bash", "-e", "-c", "x"], "x"),
            (["bash", "-o", "pipefail", "-c", "x"], "x"), (["bash", "--norc", "-c", "x"], "x"),
            (["bash", "-euo", "pipefail", "-c", "x"], "x"), (["bash", "-c", "--", "x"], "x"),
            (["/bin/zsh", "-c", "-l", "source /tmp/s && eval 'mysql db' < /dev/null && pwd -P >| /tmp/cwd"], "mysql db"),
            (["bash", "--rcfile", "x"], None), (["bash", "--norc"], None), (["bash", "--login", "s.sh"], None),
            (["bash", "script.sh", "-c", "x"], None), (["bash", "-c"], None), (["node", "-c", "x"], None),
            (["bash", "-o", "c", "s.sh"], None),
        ]
        for argv, want in cases:
            self.assertEqual(scan.unwrap_shell(argv), want, argv)


class DisplayGuard(unittest.TestCase):
    def test_summaries(self):
        cases = [
            (["curl", "-s", "https://abcdef0123456789abcdef@example.com/api"], "Fetching example.com"),
            (["curl", "https://user:pw@example.com/x"], "Fetching example.com"),
            (["curl", "https://api.example.com:8443/v1"], "Fetching api.example.com"),
            (["curl", "https://bad_host!/x"], "Downloading"),
            (["make", "DEPLOY_KEY=abcdef"], "Building"),
            (["docker", "s3cr3t=1", "ps"], "Docker"),
            (["sh", "-ec", "cd /x; ./deploy --key hunter2 prod"], "Running deploy"),
            (["zsh", "-ilc", "mysql -phunter2 db"], "Querying a database"),
            (["gh", "api", "repos/acme/private-thing/issues"], "GitHub api"),
            (["npm", "run", "deploy:KEY=s3cr3t"], "npm run"),
            (["bash", "-c", "python3 - <<'EOF'\nprint(1)\nEOF"], "Python script"),
            (["git", "status"], "Git status"), (["gh", "pr", "create"], "GitHub pr create"),
            (["sh", "-c", "npm run build"], "npm run build"), (["python3", "tools/build.py"], "Running build.py"),
            (["npx", "create-vite@latest"], "Running create-vite@latest"), (["weirdtool", "--x"], "Running weirdtool"),
            (["make"], "Building"), (["curl", "https://api.example.com/v1"], "Fetching api.example.com"),
            (["ssh", "deploy@example.com"], "Remote session on example.com"), (["gh", "auth", "status"], "GitHub auth status"),
            (["ssh", "u@host"], "Remote session on host"), (["npx", "-y", "some pkg --key hunter2"], "npx"),
            (["/x/tok=hunter2"], "Running a program"),
        ]
        for argv, want in cases:
            self.assertEqual(scan.describe(argv), want, argv)

    def test_no_leaks(self):
        cases = [
            (["git", "-c", "http.extraHeader=X-Api: abc123", "push"], ("abc123", "X-Api", "extraHeader")),
            (["ssh", "-o", "ProxyCommand=sshpass -p hunter2 ssh jump", "u@h"], ("hunter2", "ProxyCommand")),
            (["npx", "-y", "some pkg --key hunter2"], ("hunter2",)),
            (claude("cd /x && ./deploy --key hunter2 prod"), ("hunter2",)),
            (["sh", "-ec", "TOKEN=abc ./run.sh"], ("abc",)),
            (["python3", "-m", "tok=hunter2"], ("hunter2",)),
            (["cargo", "--config", "x=1", "build"], ("x=1",)),
        ]
        for argv, secrets in cases:
            out = scan.describe(argv)
            for s in secrets:
                self.assertNotIn(s, out, argv)


class Sessions(unittest.TestCase):
    def test_same_agent_chain_is_one_row(self):
        # 10 gemini -> 11 gemini (its relaunch) -> 12 gemini; 20 claude runs 21 codex directly;
        # 30 claude, whose shell (not an agent) started 31 claude: two sessions.
        agents = {10: "Gemini CLI", 11: "Gemini CLI", 12: "Gemini CLI", 20: "Claude Code", 21: "Codex",
                  30: "Claude Code", 31: "Claude Code"}
        parent = {10: 1, 11: 10, 12: 11, 20: 1, 21: 20, 30: 1, 31: 99}
        self.assertEqual(scan.fold_agents(agents, parent), {11: 10, 12: 10})

    def test_codex_background_service(self):
        # the bookkeeping half is never a session; T3 Code's own host and the service itself are
        self.assertIsNone(agent("codex", ["/h/.codex/packages/x/bin/codex", "app-server", "daemon", "pid-update-loop"]))
        self.assertEqual(agent("codex", ["codex", "app-server"]), "Codex")
        self.assertEqual(agent("codex", ["/h/bin/codex", "app-server", "--listen", "unix://", "--managed-daemon"]), "Codex")

    def test_program_folder_is_not_an_mcp_hint_in_a_shell(self):
        self.assertIsNone(scan.mcp_name(claude("/home/u/my-mcp/node_modules/.bin/jest --watch")))
        self.assertEqual(scan.mcp_name(["/opt/tools/foo-mcp/bin/server", "--stdio"]), "foo")


class RunningNow(unittest.TestCase):
    def test_follows_shells_and_wrappers_to_the_live_command(self):
        # 10 claude's shell -> 11 sudo -> 12 bash -c -> 13 pacman, and 14 a later pipeline stage
        s = scan.Scanner()
        argv = {10: claude("ls -la /x | cut -c1-30; sudo -S bash -c \"pacman -S fwupd\""), 11: ["sudo", "-S", "bash", "-c", "pacman -S fwupd"],
                12: ["bash", "-c", "pacman -S fwupd; echo ok"], 13: ["pacman", "-S", "fwupd"], 14: ["tail", "-3"],
                20: ["bash", "build.sh"], 21: ["make"]}
        procs = {p: ("x", 0, 0, p, 0) for p in argv}
        for p, a in argv.items():
            s.cmd[(p, p)] = a
        children = {10: [11], 11: [12], 12: [14, 13], 20: [21]}
        self.assertEqual(scan.describe(argv[10]), "Looking at files")       # the script's first command
        self.assertEqual(s.current(10, procs, children, {}), 13)
        self.assertEqual(scan.describe(argv[13]), "Installing packages")
        self.assertEqual(s.current(10, procs, {10: [11]}, {}), 11)           # sudo waiting for a password
        self.assertEqual(s.current(20, procs, children, {}), 20)             # a script file keeps its own name
        self.assertEqual(s.current(10, procs, {10: [11]}, {11: "Codex"}), 10)   # a nested agent has its own row

    def test_program_name_shown_unless_summary_says_it(self):
        for text, prog, want in [("Installing packages", "/usr/bin/pacman", "pacman"), ("Reading files", "jq", "jq"),
                                 ("Git status", "git", ""), ("Python script", "python3.13", ""), ("Running sudo", "sudo", ""),
                                 ("Running scan.py", "python3", "python3"), ("Shell", "-bash", ""), ("Running a program", "tok=hunter2", "")]:
            self.assertEqual(scan.proc_label(text, prog), want, (text, prog))


class WorkChain(unittest.TestCase):
    def setUp(self):
        # 10 claude's shell -> 11 python3 encode.py -> 12 ffmpeg, and 13 magick beside it
        self.s = scan.Scanner()
        self.argv = {10: claude("sed -i s/a/b/ x.txt && python3 encode.py"), 11: ["python3", "encode.py"],
                     12: ["ffmpeg", "-i", "a.mp4", "b.mp4"], 13: ["magick", "a.png", "b.png"]}
        comm = {10: "bash", 11: "python3", 12: "ffmpeg", 13: "magick"}
        self.procs = {p: (comm[p], p - 1, 0, p, 0) for p in self.argv}
        for p, a in self.argv.items():
            self.s.cmd[(p, p)] = a
        self.children = {10: [11], 11: [12, 13]}

    def chain(self, cpu, now, cur=10, text="Editing files", prog=""):
        return self.s.work_chain(10, cur, text, prog, self.procs, self.children, cpu, set(), now)

    def test_names_the_script_and_the_busy_program(self):
        self.assertEqual(self.chain({12: 30.0}, 0), "encode.py › ffmpeg")
        # The row already describes the script: only what is under it.
        s = scan.Scanner()
        s.cmd = self.s.cmd
        self.assertEqual(s.work_chain(10, 11, "Python script", "", self.procs, self.children, {12: 30.0}, set(), 0), "ffmpeg")
        # Nothing busy underneath: no line.
        self.assertEqual(scan.Scanner().work_chain(10, 10, "Editing files", "", self.procs, self.children, {12: 0.5}, set(), 0), "")

    def test_holds_steady_while_the_work_goes_on(self):
        self.assertEqual(self.chain({12: 20.0, 13: 15.0}, 0), "encode.py › ffmpeg")
        self.assertEqual(self.chain({12: 12.0, 13: 18.0}, 2), "encode.py › ffmpeg")    # a little busier: stays
        self.assertEqual(self.chain({12: 3.0, 13: 18.0}, 4), "encode.py › magick")     # far busier: moves
        self.assertEqual(self.chain({}, 4 + scan.HOLD - 1), "encode.py › magick")      # quiet: held a while
        self.assertEqual(self.chain({}, 4 + scan.HOLD + 1), "")

    def test_labels(self):
        for comm, args, want in [("python3", ["python3", "-u", "/x/tools/encode.py", "--fast"], "encode.py"),
                                 ("python3", ["python3", "-m", "pytest", "-q"], "pytest"),
                                 ("python3", ["python3", "-c", "print(1)"], "python3"),
                                 ("node", ["node", "/usr/bin/npm", "run", "dev"], "npm"),
                                 ("node", ["node", "-p", "SECRET.value", "app.js"], "node"),
                                 ("node", ["node", "-r", "dotenv/config", "app.js"], "app.js"),
                                 ("bash", ["bash", "-c", "ls"], None),
                                 ("bash", ["bash", "scripts/deploy.sh"], "deploy.sh"),
                                 ("aiwidget-3f9c2e", ["./aiwidget-3f9c2e1b7a6d5c4e"], "aiwidget"),
                                 ("ffmpeg", [], "ffmpeg")]:
            self.assertEqual(scan.work_label(comm, args), want, (comm, args))


class MainLoop(unittest.TestCase):
    def test_survives_scan_errors(self):
        class Broken:
            def scan(self):
                raise RuntimeError("boom")
        out, err = io.StringIO(), io.StringIO()
        stdin = io.StringIO("open\n")       # one tick, a message, a second tick, then EOF
        with mock.patch.object(scan, "Scanner", Broken), mock.patch.object(scan.os, "nice"), \
                mock.patch.object(scan.select, "select", lambda r, w, x, t: (r, [], [])), \
                mock.patch.object(scan.sys, "stdin", stdin), mock.patch.object(scan.sys, "stdout", out), \
                mock.patch.object(scan.sys, "stderr", err), mock.patch.object(scan.sys, "argv", ["scan.py"]):
            scan.main()
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(scan.json.loads(lines[0])["agents"], [])
        self.assertEqual(err.getvalue().count("RuntimeError: boom"), 1)


class Caches(unittest.TestCase):
    # These guard the fixes the marketplace review accepted at 0d907c1
    # (omacom/omarchy-plugin-marketplace#14916): nothing the scanner remembers may
    # outlive the processes and sessions it is about, and stored titles are only
    # the masked, 80-character text the panel shows.
    # Fake processes with pids above pid_max, so nothing real is read from /proc.
    def run_scans(self, steps, env=None, connect=None, cmds=None):
        """steps: one {pid: stat} per scan. Returns the Scanner and each scan's agents."""
        s = scan.Scanner()
        procs, snaps = {}, []
        con = mock.MagicMock()
        con.execute.return_value.fetchone.return_value = ("T" * 5000,)
        with mock.patch.object(scan.os, "listdir", lambda p: [str(pid) for pid in procs]), \
                mock.patch.object(scan, "read_stat", lambda pid: procs.get(pid)), \
                mock.patch.object(scan, "owned", lambda pid: True), \
                mock.patch.object(scan.sqlite3, "connect", connect or (lambda *a, **k: con)):
            for step in steps:
                procs.clear()
                procs.update(step)
                for pid, st in procs.items():
                    s.cmd.setdefault((pid, st[3]), (cmds or {}).get(pid, [st[0]]))
                    s.envc.setdefault((pid, st[3]), (env or {}).get(pid, {"T3CODE_THREAD_ID": "thread-%d" % pid}))
                snaps.append(s.scan()["agents"])
        return s, snaps

    A = {9000001: ("claude", 1, 0, 11, 0)}
    B = {9000002: ("claude", 1, 0, 22, 0)}

    def test_titles_go_when_the_session_does(self):
        s, snaps = self.run_scans([{**self.A, **self.B}, self.A, {}])
        self.assertEqual([a["label"] for a in snaps[0]], ["T" * 80] * 2)     # masked and cut to what is shown
        self.assertEqual(sorted(s.titles), [])
        s, snaps = self.run_scans([{**self.A, **self.B}, self.A])
        self.assertEqual(sorted(s.titles), ["thread-9000001"])

    def test_failed_lookups_go_too(self):
        def broken(*a, **k):
            raise scan.sqlite3.OperationalError("unable to open database file")
        s, snaps = self.run_scans([{**self.A, **self.B}, {}], connect=broken)
        self.assertEqual(s.titles, {})

    def test_stored_title_is_short_text(self):
        con = mock.MagicMock()
        with mock.patch.object(scan.sqlite3, "connect", lambda *a, **k: con):
            con.execute.return_value.fetchone.return_value = ("token=sample123 " + "T" * 5000,)
            title = scan.Scanner().thread_title("x")
            self.assertEqual(len(title), 80)
            self.assertNotIn("sample123", title)
            con.execute.return_value.fetchone.return_value = (12345,)       # not text: no title, no crash
            self.assertIsNone(scan.Scanner().thread_title("x"))

    def test_one_name_per_process_however_often_it_renames(self):
        steps = [{9000003: ("python%d" % i, 1, 0, 33, 0)} for i in range(50)]
        s, _ = self.run_scans(steps)
        self.assertEqual(len(s.names), 1)
        s, _ = self.run_scans(steps + [{}])
        self.assertEqual(s.names, {})

    def test_bad_claude_pid_does_not_stop_the_scan(self):
        orphans = {9000010: ("sleep", 1, 0, 40, 0), 9000011: ("sleep", 1, 0, 41, 0)}
        env = {9000010: {"CLAUDE_PID": "\u00b2"}, 9000011: {"CLAUDE_PID": "9" * 5000}}
        s, snaps = self.run_scans([{**self.A, **orphans}], env=env)
        self.assertEqual(len(snaps[0]), 1)

    def test_codex_sandbox_is_one_session(self):
        # Codex runs each command in its sandbox: 9000031 codex -> 9000032 bwrap ->
        # 9000033 codex re-run as codex-linux-sandbox -> 9000034 bash bench.sh -> 9000035 xz.
        # Beside them, 9000036 is Codex's own code-mode host. And 9000037, a Claude Code
        # that Codex started, runs in a terminal: "codex" is not VS Code.
        tree = lambda ticks: {9000030: ("alacritty", 1, 0, 60, 0),
                              9000031: ("codex", 9000030, 0, 61, 0),
                              9000032: ("bwrap", 9000031, 0, 62, 0),
                              9000033: ("codex", 9000032, 0, 63, 0),
                              9000034: ("bash", 9000033, 0, 64, 0),
                              9000035: ("xz", 9000034, ticks, 65, 0),
                              9000036: ("codex-code-mode", 9000031, 0, 66, 0),
                              9000037: ("claude", 9000031, 0, 67, 0)}
        cmds = {9000031: ["codex"], 9000032: ["bwrap", "--unshare-pid", "--argv0", "codex"],
                9000033: ["codex-linux-sandbox", "--sandbox-policy-cwd", "/w", "--", "bash", "bench.sh"],
                9000034: ["bash", "bench.sh"], 9000035: ["xz", "-9"],
                9000036: ["/opt/codex/bin/codex-code-mode-host", "--listen", "grpc+stdio://"],
                9000037: ["claude"]}
        _, snaps = self.run_scans([tree(0), tree(10 ** 6)], cmds=cmds, env={})
        self.assertEqual(sorted(a["name"] for a in snaps[1]), ["Claude Code", "Codex"])
        rows = {a["name"]: a for a in snaps[1]}
        self.assertEqual(rows["Claude Code"]["host"], "Terminal")
        tasks = rows["Codex"]["tasks"]
        self.assertEqual([(t["text"], t["chain"]) for t in tasks], [("Running bench.sh", "xz")])

    def test_every_cache_empties_when_the_processes_go(self):
        # An agent running "python3 encode.py", which runs a busy ffmpeg, so the
        # task gets a "↳ encode.py › ffmpeg" line. Covers every cache, including
        # any added later: each one must be empty once the processes are gone.
        tree = lambda ticks: {**self.A,
                              9000020: ("bash", 9000001, 0, 50, 0),
                              9000021: ("python3", 9000020, 0, 51, 0),
                              9000022: ("ffmpeg", 9000021, ticks, 52, 0)}
        cmds = {9000020: claude("python3 encode.py"), 9000021: ["python3", "encode.py"],
                9000022: ["ffmpeg", "-i", "a.mp4", "b.mp4"]}
        s, snaps = self.run_scans([tree(0), tree(10 ** 6)], cmds=cmds)
        self.assertIn("ffmpeg", snaps[1][0]["tasks"][0]["chain"])
        self.assertTrue(s.workers)
        s, _ = self.run_scans([tree(0), tree(10 ** 6), {}], cmds=cmds)
        caches = {k: v for k, v in vars(s).items() if isinstance(v, dict)}
        self.assertIn("workers", caches)
        self.assertEqual({k: v for k, v in caches.items() if v}, {})


if __name__ == "__main__":
    unittest.main()

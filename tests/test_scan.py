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


if __name__ == "__main__":
    unittest.main()

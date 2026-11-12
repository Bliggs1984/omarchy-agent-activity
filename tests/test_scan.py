"""Run with: python3 -I tests/test_scan.py  (from the plugin folder)"""
import importlib.util
import os
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("scan", os.path.join(HERE, "..", "scan.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

CLAUDE_WRAP = ("source /home/u/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && "
               "shopt -u extglob 2>/dev/null || true && eval '{}' && pwd -P >| /tmp/claude-abcd-cwd")


def claude(cmd):
    return ["/usr/bin/bash", "-c", CLAUDE_WRAP.format(cmd.replace("'", "'\"'\"'"))]


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


if __name__ == "__main__":
    unittest.main()

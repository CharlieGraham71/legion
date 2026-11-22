import os
import shutil
import subprocess
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from app.auxiliary import commandNeedsShell, formatCommandQProcess
from app.nmap_command import build_nmap_command


class CommandNeedsShellTest(unittest.TestCase):
    def test_plain_commands_do_not(self):
        for command in (
            "nmap -Pn -sV -p 80 10.0.0.5 -oA /tmp/out",
            "nmap -Pn 10.0.0.5 -p 445 --script=smb-vuln-*.nse --script-args=unsafe=1",
            "smbmap -H 10.0.0.5 -P 445 --no-write-check -q",
            "rpcclient 10.0.0.5 -p 445 -U '%' -c 'srvinfo;enumdomusers;netshareenumall'",
            'curl -H "X-Test: a|b;c" http://10.0.0.5/',
            r"echo a\;b",
            "",
        ):
            self.assertFalse(commandNeedsShell(command), command)

    def test_shell_scripts_do(self):
        for command in (
            "(command -v katana >/dev/null 2>&1 && katana -u http://10.0.0.5) || echo katana not found",
            "if command -v netexec >/dev/null 2>&1; then netexec smb 10.0.0.5; else echo netexec not found; fi",
            "medusa -h 10.0.0.5 -u root -P ./wordlists/snmp-default.txt -M snmp | grep SUCCESS",
            "sqlmap --url=http://10.0.0.5 --batch > /tmp/out",
            "smbmap -H 10.0.0.5 -q | tee /tmp/out.txt",
        ):
            self.assertTrue(commandNeedsShell(command), command)


class FormatCommandQProcessTest(unittest.TestCase):
    def test_plain_command_is_executed_directly(self):
        self.assertEqual(("nmap", ["-sV", "-p", "80", "10.0.0.5"]), formatCommandQProcess("nmap -sV -p 80 10.0.0.5"))

    def test_quoted_operators_stay_arguments(self):
        program, arguments = formatCommandQProcess("rpcclient 10.0.0.5 -U '%' -c 'srvinfo;enumdomusers'")
        self.assertEqual("rpcclient", program)
        self.assertEqual(["10.0.0.5", "-U", "%", "-c", "srvinfo;enumdomusers"], arguments)

    def test_shell_script_goes_to_sh(self):
        command = "(command -v nosuchtool >/dev/null 2>&1 && nosuchtool) || echo nosuchtool not found"
        program, arguments = formatCommandQProcess(command)
        self.assertEqual(("/bin/sh", ["-c", command]), (program, arguments))
        result = subprocess.run([program, *arguments], capture_output=True, text=True)
        self.assertEqual("nosuchtool not found\n", result.stdout)

    def test_lists_and_empty_input_are_unchanged(self):
        self.assertEqual(("nmap", ["-sV"]), formatCommandQProcess(["nmap", "-sV"]))
        self.assertEqual(("", []), formatCommandQProcess(""))
        self.assertEqual(("", []), formatCommandQProcess("   "))

    def test_command_bar_input_never_reaches_a_shell(self):
        tmp = tempfile.mkdtemp(prefix="legion-fmt-")
        self.addCleanup(shutil.rmtree, tmp, True)
        marker = os.path.join(tmp, "marker")
        typed_commands = (f"-p 80; touch {marker}", f"-p 80 && touch {marker}", f"$(touch {marker})",
                          f"-p 80 | tee {marker}")
        for typed in typed_commands:
            command = build_nmap_command(typed, "10.0.0.5") + " -oA '/tmp/some dir/out'"
            self.assertFalse(commandNeedsShell(command), typed)
            program, arguments = formatCommandQProcess(command)
            self.assertEqual("nmap", program, typed)
            self.assertEqual(["-oA", "/tmp/some dir/out"], arguments[-2:], typed)


if __name__ == "__main__":
    unittest.main()

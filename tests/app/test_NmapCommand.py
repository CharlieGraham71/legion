import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

from app.nmap_command import NmapCommandError, PRESETS, build_nmap_command, has_output_option


class BuildNmapCommandTest(unittest.TestCase):
    def test_options_get_the_target_appended(self):
        self.assertEqual("nmap -sV -p 1-1000 192.168.1.10", build_nmap_command("-sV -p 1-1000", "192.168.1.10"))

    def test_no_options_is_a_plain_scan(self):
        self.assertEqual("nmap 192.168.1.10", build_nmap_command("", "192.168.1.10"))
        self.assertEqual("nmap 192.168.1.10", build_nmap_command("   ", "192.168.1.10"))

    def test_a_pasted_full_command_does_not_double_nmap(self):
        self.assertEqual("nmap -F 10.0.0.5", build_nmap_command("nmap -F", "10.0.0.5"))
        self.assertEqual("nmap -F 10.0.0.5", build_nmap_command("sudo nmap -F", "10.0.0.5"))

    def test_target_already_typed_is_not_repeated(self):
        self.assertEqual("nmap -F 10.0.0.5", build_nmap_command("nmap -F 10.0.0.5", "10.0.0.5"))

    def test_placeholder_says_where_the_target_goes(self):
        self.assertEqual("nmap 10.0.0.5 -p 80", build_nmap_command("[IP] -p 80", "10.0.0.5"))

    def test_a_host_must_be_selected(self):
        with self.assertRaises(NmapCommandError):
            build_nmap_command("-sV", "")
        with self.assertRaises(NmapCommandError):
            build_nmap_command("-sV", None)

    def test_target_cannot_be_an_option_or_contain_spaces(self):
        for target in ("-iL", "10.0.0.5 10.0.0.6"):
            with self.assertRaises(NmapCommandError):
                build_nmap_command("-sV", target)

    def test_unbalanced_quotes_are_reported(self):
        with self.assertRaises(NmapCommandError):
            build_nmap_command('--script "http-title', "10.0.0.5")

    def test_multiple_lines_are_refused(self):
        with self.assertRaises(NmapCommandError):
            build_nmap_command("-sV\nrm -rf /", "10.0.0.5")

    def test_shell_syntax_only_ever_reaches_nmap_as_arguments(self):
        # Run each built command through a real shell with a stand-in nmap that lists its arguments: whatever was
        # typed must arrive as literal arguments, and nothing else may run.
        tmp = tempfile.mkdtemp(prefix="legion-nmapcmd-")
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = os.path.join(tmp, "nmap")
        with open(fake, "w", encoding="utf-8") as handle:
            handle.write('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
        os.chmod(fake, 0o755)
        marker = os.path.join(tmp, "marker")
        env = dict(os.environ, PATH=tmp + os.pathsep + os.environ.get("PATH", ""))
        typed_commands = (
            f"-p 80; touch {marker}", f"-p 80 && touch {marker}", f"-p 80 | tee {marker}", f"$(touch {marker})",
            f"`touch {marker}`", f"-p 80 > {marker}", f"-p 80 & touch {marker}",
        )
        for typed in typed_commands:
            command = build_nmap_command(typed, "10.0.0.5")
            result = subprocess.run(["/bin/sh", "-c", command], env=env, capture_output=True, text=True, cwd=tmp)
            self.assertEqual(0, result.returncode, typed)
            self.assertEqual(shlex.split(typed) + ["10.0.0.5"], result.stdout.splitlines(), typed)
            self.assertFalse(os.path.exists(marker), typed)
            self.assertEqual("nmap", shlex.split(command)[0], typed)

    def test_script_globs_stay_one_argument(self):
        command = build_nmap_command('--script "http-*" -p 80', "10.0.0.5")
        self.assertEqual(["nmap", "--script", "http-*", "-p", "80", "10.0.0.5"], shlex.split(command))

    def test_presets_all_build(self):
        for _label, options in PRESETS:
            self.assertTrue(build_nmap_command(options, "10.0.0.5").endswith(" 10.0.0.5"))


class HasOutputOptionTest(unittest.TestCase):
    def test_detects_own_output_options(self):
        for command in ("nmap -oA out 10.0.0.5", "nmap -oX out.xml 10.0.0.5", "nmap -oN- 10.0.0.5",
                        "nmap -oG out 10.0.0.5"):
            self.assertTrue(has_output_option(command), command)

    def test_plain_commands_have_none(self):
        for command in ("nmap -sV 10.0.0.5", "nmap -O 10.0.0.5", "nmap --open 10.0.0.5"):
            self.assertFalse(has_output_option(command), command)


if __name__ == "__main__":
    unittest.main()

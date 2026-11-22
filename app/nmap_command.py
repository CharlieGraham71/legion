#!/usr/bin/env python3

"""
LEGION (https://shanewilliamscott.com)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Builds the command for the nmap command bar of the desktop UI: the options the operator typed, run by nmap against
the selected host. No Qt imports, so it can be tested on its own.
"""

import shlex

TARGET_PLACEHOLDER = "[IP]"

# Shown in the drop-down of the command bar: (label, options).
PRESETS = (
    ("Quick scan (top 100 ports)", "-T4 -F"),
    ("Service versions", "-sV"),
    ("Service versions, all TCP ports", "-sV -p-"),
    ("Default scripts and versions", "-sC -sV"),
    ("OS detection", "-O"),
    ("Aggressive (OS, versions, scripts, traceroute)", "-A -T4"),
    ("Top 100 UDP ports", "-sU --top-ports 100"),
    ("Vulnerability scripts", "-sV --script vuln"),
    ("Ping only (is it up?)", "-sn"),
)

_LEADING_WORDS = ("sudo", "nmap")


class NmapCommandError(ValueError):
    """The typed text cannot be turned into an nmap command; the message is shown to the operator."""


def build_nmap_command(options_text, target, nmap_program="nmap"):
    """Return the command line that runs nmap with ``options_text`` against ``target``.

    ``options_text`` is what the operator typed: nmap options, with or without a leading ``nmap`` (or ``sudo nmap``),
    so a command copied from a terminal works. The target is appended, unless the text already names it or uses the
    ``[IP]`` placeholder to say where it goes.

    Only nmap is ever run. Every argument is quoted in the result, so shell syntax in the text (``;``, ``|``, ``&&``,
    ``$(...)``) reaches nmap as a plain argument and is never interpreted, whether or not the command is later started
    through a shell.
    """
    target = str(target or "").strip()
    if not target:
        raise NmapCommandError("Select a host first.")
    if target.startswith("-") or any(ch.isspace() for ch in target):
        raise NmapCommandError(f"'{target}' is not a usable target.")

    text = str(options_text or "")
    if any(ch in text for ch in ("\n", "\r", "\x00")):
        raise NmapCommandError("The command must be a single line.")

    try:
        arguments = shlex.split(text)
    except ValueError as exc:
        raise NmapCommandError(f"Could not read the options: {exc}.") from exc

    for word in _LEADING_WORDS:
        if arguments and arguments[0] == word:
            arguments = arguments[1:]

    has_target = False
    resolved = []
    for argument in arguments:
        if TARGET_PLACEHOLDER in argument:
            argument = argument.replace(TARGET_PLACEHOLDER, target)
            has_target = True
        elif argument == target:
            has_target = True
        resolved.append(argument)

    if not has_target:
        resolved.append(target)

    return shlex.join([str(nmap_program or "nmap"), *resolved])


def has_output_option(command):
    """True when the command already carries an nmap output option of its own (-oA, -oX, -oN, -oG, -oS)."""
    try:
        arguments = shlex.split(str(command or ""))
    except ValueError:
        return False
    return any(argument[:3] in ("-oA", "-oX", "-oN", "-oG", "-oS") for argument in arguments)

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

Builds the command for the nmap command bar of the desktop UI: what the operator typed, run by nmap as typed. If the
text names no target, the selected host is used. No Qt imports, so it can be tested on its own.
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

# nmap options whose value is the next word, so that word is not a target ("-p 80", "-e eth0", "-S 10.0.0.1").
_VALUE_OPTIONS = frozenset((
    "-p", "-e", "-S", "-g", "-D", "-b", "-sI", "-T", "-oN", "-oX", "-oG", "-oA", "-oS", "-oM",
    "--exclude", "--excludefile", "--exclude-ports", "--dns-servers", "--top-ports", "--port-ratio",
    "--version-intensity", "--script", "--script-args", "--script-args-file", "--script-help",
    "--source-port", "--proxies", "--proxy", "--data", "--data-string", "--data-length", "--ip-options", "--ttl",
    "--spoof-mac", "--mtu", "--max-retries", "--host-timeout", "--script-timeout", "--scan-delay",
    "--max-scan-delay", "--min-rate", "--max-rate", "--min-parallelism", "--max-parallelism", "--min-hostgroup",
    "--max-hostgroup", "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout", "--stats-every",
    "--stylesheet", "--datadir", "--servicedb", "--versiondb", "--resume", "--scanflags", "--max-os-tries",
    "--nsock-engine", "--sctp-vtag", "--scan-flags",
))
# Options that supply the targets themselves (a file, or random hosts).
_TARGET_SOURCE_OPTIONS = ("-iL", "-iR")


class NmapCommandError(ValueError):
    """The typed text cannot be turned into an nmap command; the message is shown to the operator."""


def _split(options_text):
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
    return arguments


def _looks_like_target(word):
    # An address, range, network or host name: "10.0.0.5", "10.0.0.0/24", "10.0.0.1-50", "fe80::1", "router".
    # A bare number or port list ("4", "1-1000", "80,443") is the value of some option, not a target.
    if not word or word[0] in "-,/":
        return False
    return any(ch.isalpha() or ch in ".:" for ch in word)


def typed_targets(arguments):
    """The targets named in a list of nmap arguments, and whether an option (-iL, -iR) supplies targets itself."""
    targets = []
    target_source = False
    skip_next = False
    for argument in arguments:
        if skip_next:
            skip_next = False
            continue
        if argument.startswith(_TARGET_SOURCE_OPTIONS):
            target_source = True
            skip_next = argument in _TARGET_SOURCE_OPTIONS
            continue
        if argument in _VALUE_OPTIONS:
            skip_next = True
            continue
        if argument.startswith("-"):
            continue
        if _looks_like_target(argument):
            targets.append(argument)
    return targets, target_source


def command_target(options_text, selected_host):
    """What a command would scan: (own, targets). ``own`` is True when the typed text names its targets itself,
    so the selected host is not added; ``targets`` lists them ([] when they come from -iL/-iR or there are none).
    Unreadable text counts as naming nothing."""
    try:
        arguments = _split(options_text)
    except NmapCommandError:
        arguments = []
    selected_host = str(selected_host or "").strip()
    if TARGET_PLACEHOLDER in " ".join(arguments):
        return False, ([selected_host] if selected_host else [])
    targets, target_source = typed_targets(arguments)
    if targets or target_source:
        return True, targets
    return False, ([selected_host] if selected_host else [])


def build_nmap_command(options_text, target, nmap_program="nmap"):
    """Return the nmap command line for what the operator typed.

    ``options_text`` is run as typed, with or without a leading ``nmap`` (or ``sudo nmap``), so a command copied
    from a terminal works. When it names its own target (an address, range, network or host name, or -iL/-iR) it is
    left alone. Otherwise ``target`` (the selected host) is appended, or put where the ``[IP]`` placeholder is.

    Only nmap is ever run. Every argument is quoted in the result, so shell syntax in the text (``;``, ``|``, ``&&``,
    ``$(...)``) reaches nmap as a plain argument and is never interpreted, whether or not the command is later started
    through a shell.
    """
    arguments = _split(options_text)
    target = str(target or "").strip()
    if target.startswith("-") or any(ch.isspace() for ch in target):
        raise NmapCommandError(f"'{target}' is not a usable target.")

    uses_placeholder = any(TARGET_PLACEHOLDER in argument for argument in arguments)
    targets, target_source = typed_targets(arguments)
    if uses_placeholder:
        if not target:
            raise NmapCommandError("Select a host first: [IP] stands for the selected host.")
        arguments = [argument.replace(TARGET_PLACEHOLDER, target) for argument in arguments]
    elif not targets and not target_source:
        if not target:
            raise NmapCommandError("Type a target after the options (for example 192.168.1.10), or select a host.")
        arguments.append(target)

    return shlex.join([str(nmap_program or "nmap"), *arguments])


def has_output_option(command):
    """True when the command already carries an nmap output option of its own (-oA, -oX, -oN, -oG, -oS)."""
    try:
        arguments = shlex.split(str(command or ""))
    except ValueError:
        return False
    return any(argument[:3] in ("-oA", "-oX", "-oN", "-oG", "-oS") for argument in arguments)

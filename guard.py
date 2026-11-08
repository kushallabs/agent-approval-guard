#!/usr/bin/env python3
"""Inspect Claude Code approval artifacts without executing commands or printing secrets."""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys


MAX_INPUT = 1024 * 1024
MAX_COMMAND = 32 * 1024
MAX_COMMITS = 1000
LOCAL = b".claude/settings.local.json"
SHARED = b".claude/settings.json"
REGULAR_FILE = {b"100644", b"100755"}
SECRET_NAME = re.compile(
    r"(?:PGPASSWORD|MYSQL_PWD|(?:[A-Z0-9]+_)*(?:PASSWORD|PASSWD|TOKEN|API_?KEY|CLIENT_?SECRET|SECRET_?KEY|ACCESS_?KEY|PRIVATE_?KEY))",
    re.IGNORECASE,
)
SECRET_FLAGS = {"--password", "--passwd", "--token", "--api-key", "--client-secret"}
REFERENCE = re.compile(r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})|<[A-Za-z_][A-Za-z0-9_. -]*>")
PROVIDER_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
    r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{15,})"
)
HEADER = re.compile(r"""(?:Authorization\s*:\s*(?:Bearer|Basic)\s+|X-API-Key\s*:\s*)([^\s"'()]+)""", re.I)
URL_PASSWORD = re.compile(
    r"\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?)"
    r"://[^\s:/@]*:([^\s/@]+)@", re.I,
)


class ScanError(Exception):
    """A boundary could not be checked."""


def literal(value):
    value = value.strip().strip("\"'")
    return bool(value and value != "*" and not REFERENCE.fullmatch(value))


def command_findings(command):
    if len(command) > MAX_COMMAND:
        return {"command-too-large"}
    if command.startswith("Bash(") and command.endswith(")"):
        command = command[5:-1]
    findings = set()
    if PROVIDER_TOKEN.search(command):
        findings.add("provider-token")
    if any(literal(match[1]) for match in HEADER.finditer(command)):
        findings.add("authorization-header")
    if any(literal(match[1]) for match in URL_PASSWORD.finditer(command)):
        findings.add("url-password")

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        words = list(lexer)
    except ValueError:
        words = command.split()
    program = None
    for i, word in enumerate(words):
        key, separator, value = word.partition("=")
        following = words[i + 1] if i + 1 < len(words) else ""
        if word and all(char in "();<>|&" for char in word):
            program = None
        if separator and SECRET_NAME.fullmatch(key) and literal(value):
            findings.add("credential-assignment")
        if key in SECRET_FLAGS and literal(value if separator else following):
            findings.add("credential-argument")
        if program == "sshpass" and word == "-p" and literal(following):
            findings.add("credential-argument")
        if program in {"sshpass", "mysql", "mariadb"} and word.startswith("-p") and literal(word[2:]):
            findings.add("credential-argument")
        if word.rsplit("/", 1)[-1] in {"sshpass", "mysql", "mariadb"}:
            program = word.rsplit("/", 1)[-1]
    return findings


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate settings key")
        result[key] = value
    return result


def settings_findings(content):
    try:
        settings = json.loads(content.decode("utf-8-sig"), object_pairs_hook=strict_object)
    except (ValueError, RecursionError):
        return {"unreadable-settings"}
    if not isinstance(settings, dict):
        return {"unreadable-settings"}
    findings = set()
    remaining = [("", settings)]
    while remaining:
        key, value = remaining.pop()
        if isinstance(value, dict):
            remaining.extend(value.items())
        elif isinstance(value, list):
            remaining.extend((key, item) for item in value)
        elif isinstance(value, str):
            if SECRET_NAME.fullmatch(key) and literal(value):
                findings.add("credential-setting")
            findings.update(command_findings(value))
    return findings


def git(*args):
    try:
        return subprocess.run(
            ["git", "--no-pager", "-c", "core.fsmonitor=false", *args],
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"},
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScanError("Git could not read the requested snapshot. Check the repository and refs.") from error


def commit_id(ref):
    return git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}").strip().decode("ascii")


def changes(raw):
    fields = iter(raw.split(b"\0"))
    for header in fields:
        if header:
            _, mode, _, oid, _ = header.split()
            yield next(fields), mode, oid


def snapshot(mode, refs):
    diff_options = (
        "--raw", "--no-abbrev", "-z", "--diff-filter=AMTU", "--no-renames",
        "--no-ext-diff", "--no-textconv", "--ignore-submodules=none",
    )
    if mode == "staged":
        for path, file_mode, oid in changes(git("diff", "--cached", *diff_options, "--")):
            yield path, file_mode, oid, None
    elif mode == "tree":
        head = commit_id(refs[0])
        for row in git("ls-tree", "-r", "-z", "--full-tree", head).split(b"\0"):
            if row:
                header, path = row.split(b"\t", 1)
                file_mode, _, oid = header.split()
                yield path, file_mode, oid, head
    else:
        if git("rev-parse", "--is-shallow-repository").strip() != b"false":
            raise ScanError("A range scan requires a full Git history.")
        base, head = (commit_id(ref) for ref in refs)
        commits = git("rev-list", f"--max-count={MAX_COMMITS + 1}", f"{base}..{head}", "--").split()
        if len(commits) > MAX_COMMITS:
            raise ScanError("Range exceeds 1000 commits. Scan smaller ranges.")
        for commit in commits:
            rev = commit.decode("ascii")
            raw = git("diff-tree", "--root", "-r", "-m", "--no-commit-id", *diff_options, rev, "--")
            for path, file_mode, oid in changes(raw):
                yield path, file_mode, oid, rev


def artifact(path):
    suffix = b"/".join(path.lower().split(b"/")[-2:])
    return suffix if suffix in {LOCAL, SHARED} else None


def inspect(file_mode, oid, kind):
    if kind == LOCAL:
        return {"local-settings-in-git"}
    if file_mode not in REGULAR_FILE:
        return {"settings-not-regular-file"}
    oid = oid.decode("ascii")
    if int(git("cat-file", "-s", oid)) > MAX_INPUT:
        return {"settings-too-large"}
    return settings_findings(git("cat-file", "blob", oid))


def scan(mode, refs):
    inspected = set()
    blocked = False
    for path, file_mode, oid, rev in snapshot(mode, refs):
        kind = artifact(path)
        key = (path, file_mode, oid)
        if kind is None or key in inspected:
            continue
        inspected.add(key)
        rules = inspect(file_mode, oid, kind)
        if rules:
            blocked = True
            location = kind.decode("ascii")
            if path != kind:
                location += " path-id=" + hashlib.sha256(path).hexdigest()[:12]
            if rev:
                location += " commit=" + rev
            print(f"BLOCK {location} [{', '.join(sorted(rules))}]")
    if not blocked:
        print("OK: no findings in the selected Claude settings artifacts.")
    return int(blocked)


def claude_hook():
    reason = "Approval Guard could not inspect the Bash tool input."
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ValueError("Input too large")
        event = json.loads(payload, object_pairs_hook=strict_object)
        if event["tool_name"] != "Bash":
            return
        command = event["tool_input"]["command"]
        if not isinstance(command, str):
            raise ValueError("Invalid command")
        findings = command_findings(command)
        if not findings:
            return
        if "command-too-large" not in findings:
            reason = "Approval Guard found a possible inline credential. Use a credential helper or a variable reference."
    except (ValueError, TypeError, KeyError, RecursionError):
        pass
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("staged", help="Scan blobs staged for commit")
    commands.add_parser("tree", help="Scan the tracked files in one commit").add_argument("ref", nargs="?", default="HEAD")
    history = commands.add_parser("range", help="Scan Claude settings changes in every commit in BASE..HEAD")
    history.add_argument("base")
    history.add_argument("head")
    commands.add_parser("claude-hook", help="Read a Claude Code PreToolUse event from stdin")
    args = parser.parse_args()
    if args.mode == "claude-hook":
        claude_hook()
        return 0
    refs = ()
    if args.mode == "tree":
        refs = (args.ref,)
    elif args.mode == "range":
        refs = (args.base, args.head)
    try:
        return scan(args.mode, refs)
    except ScanError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

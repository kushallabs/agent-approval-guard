# Agent Approval Guard

A small, offline guard from Kushal Labs for credentials retained in Claude Code approvals. It rejects selected inline credentials before a Bash tool call and inspects Claude settings at the Git boundary. It reads the staged blob or commit object directly, so editing the working copy or cleaning up a later commit cannot hide an earlier finding.

[Incident analysis and response playbook](docs/analysis.md)

## What it checks

| Boundary | Policy |
| --- | --- |
| Claude Code Bash hook | Deny commands containing selected credential assignments, password arguments, authentication headers, credential-bearing URLs or provider-token patterns. |
| Git staging and history | Block any `.claude/settings.local.json` file, including one force-added despite an ignore rule. Inspect shared `.claude/settings.json` for the same patterns and direct secret values under credential-shaped keys. |
| Output | Report the artifact type, rule IDs, and a commit ID when available. For nested or nonstandard-case paths, report a SHA-256 path fingerprint. Never print file contents, matched strings or untrusted path names. |

The scanner needs Python 3.10+ and Git for repository scans. It runs offline with the Python standard library. It inspects selected Claude settings files and direct Bash input. Use a general scanner for arbitrary files, logs, generated archives, encoded values and wider Git history. The hook depends on the trusted client loading it. Keep the normal terminal sandbox in place.

## Run it

Clone this repository outside the project you intend to scan. Run the following commands from the project repository, using the absolute path to the trusted guard:

```sh
python3 /absolute/path/to/agent-approval-guard/guard.py staged
python3 /absolute/path/to/agent-approval-guard/guard.py tree HEAD
python3 /absolute/path/to/agent-approval-guard/guard.py range BASE_SHA HEAD_SHA
```

`staged` uses the index. `tree` checks the tracked snapshot at a commit. `range` checks changed artifacts in every commit reachable from the head and absent from the base, including intermediate commits and merge changes. Use a full clone for range scans and split ranges above 1,000 commits. An invalid, duplicate-key or oversized shared settings file is blocked. The file limit is 1 MiB and the individual string limit is 32 KiB.

Git modes exit with **0** for a clean scan, **1** for a finding, and **2** for a scan error. To locate a nested finding locally, list candidate paths with `git ls-files -- ':(glob)**/.claude/settings*.json'` and compare the first 12 hex digits of SHA-256 over the Git path bytes.

## Block a commit

Add this line to the existing pre-commit hook, before any early success return. If the repository uses a hook manager, put the command in that manager's pre-commit sequence. Use a guard copy that the agent and scanned branch cannot modify.

```sh
python3 /absolute/path/to/agent-approval-guard/guard.py staged || exit $?
```

Add `**/.claude/settings.local.json` to the repository's `.gitignore`. For CI, run `range` with the trusted pull request base and head SHAs, using a full checkout and a guard pinned to a reviewed commit outside the pull request's checkout. Run it without secrets or execution of PR code. Require the check from a trusted workflow to block merges. A pull request check runs after a push, so keep the local hook and server-side push protection in the chain. [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

## Block a Bash call in Claude Code

Merge this entry into the existing `hooks.PreToolUse` list in trusted user or managed settings. Preserve any existing hooks. Use an absolute, trusted path, and quote it in the command if it contains spaces.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /absolute/path/to/agent-approval-guard/guard.py claude-hook"
          }
        ]
      }
    ]
  }
}
```

A clean request returns no permission override. A hit returns a denial with a generic message. The hook sees the Bash request after the agent has formed it. A secret already supplied to the model or retained in a transcript needs separate handling. Use a credential helper or a short-lived, scoped identity so the literal value stays outside the agent's inputs. [Claude Code hook reference](https://code.claude.com/docs/en/hooks#pretooluse)

## Verify with synthetic data

```sh
python3 -m unittest discover -s tests -v
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"PGPASSWORD=synthetic-test-only psql"}}' | python3 guard.py claude-hook
```

The second command prints a denial with no credential value. The tests use fabricated credentials and isolated Git repositories. They cover a blocked commit, a force-added local file, a dirty working tree, a credential removed at the branch tip, benign variable references, a symlink, invalid settings and redacted output.

MIT licensed. See [security reporting](SECURITY.md).

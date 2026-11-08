# How a Claude Code approval became a Git exposure

Research checked on 8 November 2026. This case covers approval persistence in Claude Code and a separate question for other coding agents about where they store tool inputs.

## What happened

An agent proposes a shell command carrying an inline database password, API token or authentication header. A developer approves it with the standing approval option. If the resulting permission rule retains the literal, the approval puts a second copy into project-local settings. That file can be staged and pushed, or bundled with a project. The same class of data can also appear in shared settings and transcripts. Git history keeps earlier versions after a subsequent deletion. [Claude Code settings](https://code.claude.com/docs/en/settings#keep-personal-settings-out-of-a-repository) · [Original 2025 issue](https://github.com/anthropics/claude-code/issues/5544) · [Apiiro study](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again)

Apiiro's November 5 study classified credentials in **1,122 of 104,185** public copies of the local settings file. The researchers assessed candidate values from their shape and context. Credential validity and abuse were outside the scope of the count. The authors reported that 215 files escaped detection by both scanners in their comparison. Ordinary passwords embedded in shell arguments can lack the format that identifies a provider token. [Apiiro study and method](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again)

## Where each safeguard applies

| Safeguard | What it controls | How this case can still occur |
| --- | --- | --- |
| Permission prompts and sandboxing | Whether a command may run, what files it can access, and where it can connect | The approval was an authorized action. Persisting its raw argument is a separate data-handling operation. A read or edit denial on a settings path also has to be evaluated against which component writes the file. |
| Git global excludes and project ignore rules | Whether an untracked file appears as an ordinary add candidate | `git add -f` can stage it. Ignore rules leave already tracked paths in the index and do not travel with every developer's global configuration. |
| Pre-commit and CI | Whether selected content clears a repository policy | Local hooks can be skipped. An endpoint-only PR diff can miss a secret added and removed in the same branch. CI on a public PR starts after GitHub has received the commits. |
| Provider push protection and secret scanning | Whether supported credential patterns can be stopped or detected at the server | An application password may lack a recognizable format. Use contextual rules for the artifact as an additional layer. |

[Claude Code permissions](https://code.claude.com/docs/en/permissions) · [Git ignore semantics](https://git-scm.com/docs/gitignore) · [Git add](https://git-scm.com/docs/git-add) · [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

## What Anthropic has shipped

- Claude Code documents a global Git exclude for the local file when it creates it. Its guidance says to add an ignore rule yourself for a manually created file. [Settings documentation](https://code.claude.com/docs/en/settings)
- Organizations can set `allowManagedPermissionRulesOnly` to restrict permission rules to managed settings. Claude Code documents that this hides rule-saving choices in the permission flow. This reduces new local standing rules. Existing files, commits and transcripts need their own cleanup. [Permissions](https://code.claude.com/docs/en/permissions#managed-settings) · [Hook behavior](https://code.claude.com/docs/en/hooks#permissionrequest)
- Version **2.1.319**, released November 6, lists separate fixes for a Bash permission-check bypass involving a crafted environment prefix and for a worktree sandbox escape. Its release notes do not identify those fixes as a change to scrubbing saved approvals. A Claude Code team member said they were investigating prevention. As of this check, we found no public confirmation of an approval-value scrubbing fix in the reviewed release notes or statement. [Release notes](https://github.com/anthropics/claude-code/releases/tag/v2.1.319) · [Team member's comment](https://news.ycombinator.com/item?id=50407882)

## Codex and Google Antigravity

The comparable question is **what gets persisted when approval is remembered**, along with what lands in transcripts, logs and project files. Codex documents user-level `prefix_rule` entries, trusted project rules and admin restrictions. Review suggested prefixes and keep credentials out of them. Google Antigravity documents command allow and deny rules, an approval workflow, and a terminal sandbox. The evidence in this case concerns Claude Code. Establishing an exposure in either other product would require a versioned, synthetic reproduction that inspects the saved bytes. [Codex rules](https://learn.chatgpt.com/docs/agent-configuration/rules) · [Antigravity CLI settings](https://antigravity.google/docs/features?tab=cli#customize-with-settingsjson) · [Antigravity sandbox](https://antigravity.google/docs/sandbox?tab=cli)

## Prevent, detect and recover

1. **Prevent the extra copy.** Keep literal credentials out of prompts, command arguments, URLs and approval rules. Use a credential helper or short-lived, scoped identity where supported. For GitHub Actions deployments, exchange a workload identity token for short-lived cloud access. Approve the specific operation rather than a general shell or command runner. [GitHub Actions OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect)
2. **Catch it before Git.** Block local-only settings by path, even when they currently contain no credentials. Keep team settings shareable and scan their values. Enforce checks on staged blobs and incoming commits. Enable supported push protection and run a broader redacted scanner over relevant repository history and artifacts. [Gitleaks](https://github.com/gitleaks/gitleaks) · [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)
3. **Triage a suspected exposure.** Establish which refs, PRs, logs, forks and published archives contained the value and who could access them. Revoke or rotate the affected credential first, review provider logs for its scope and lifetime, then remove the saved rule and tracked material. Coordinate any Git history rewrite, and check for copies in forks, clones or build outputs. Never test someone else's credential. [GitHub removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)

## Existing tools and the Kushal Labs contribution

- **claudleak** hunts for coding-agent artifacts in public GitHub repositories and uses TruffleHog. It provides useful exposure research across tools. [claudleak source](https://github.com/hazcod/claudleak) · [ironPeak's write-up](https://ironpeak.be/blog/leaking-secrets-from-the-claud/)
- **Gitleaks and TruffleHog** cover broad repository scanning with configurable detection. Existing Claude hooks also block sensitive operations or inline credentials. Use the tool that matches the boundary you need. [Gitleaks](https://github.com/gitleaks/gitleaks) · [TruffleHog](https://github.com/trufflesecurity/trufflehog) · [Example existing hook](https://github.com/Prime-agentai/agent-approval-gate)
- **Agent Approval Guard** pairs a Claude Bash hook with a policy for Claude settings, using the actual staged object and every selected incoming commit. The default output excludes command contents and arbitrary paths. The included synthetic tests show where the policy works. It is a narrow complement to general scanners.

## What we'd expect to improve next

The highest-value vendor change would separate the permission rule from the raw command. Save a typed operation, normalized safe argument constraints and references to credential handles. Refuse standing approval when a literal credential is present. Keep approvals narrowly scoped to a project, identity, and purpose, with expiry and a review trail. Apply the same controls to exported transcripts and bundles. These are design directions, with short-lived CI identity and centrally managed permission rules already available today. [GitHub Actions OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect) · [Claude managed permissions](https://code.claude.com/docs/en/permissions#managed-settings)

Before extending this tool to other agents, reproduce each artifact path and persistence behavior on named versions. An independent synthetic corpus that compares what provider-pattern scanners, contextual checks and path rules catch would make a stronger next contribution than adding support based on filenames alone.

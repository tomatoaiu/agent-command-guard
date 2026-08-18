# agent-command-guard

An AST- and path-aware `PreToolUse` guard for shell and direct file operations
proposed by coding agents.

It parses POSIX shell input with
[`mvdan.cc/sh`](https://github.com/mvdan/sh) and native Windows input with the
PowerShell parser. It walks commands and redirections (including pipelines,
subshells, command substitutions, and literal nested-shell payloads), and
returns one of three decisions:

- `allow`: continue without output
- `review`: ask for confirmation when the host supports it; otherwise deny
- `block`: deny the command

The guard emits hook responses compatible with Claude Code and Codex
integrations that use the Claude-style `PreToolUse` JSON protocol.

Two constructs are resolved from the source text rather than treated as opaque,
because leaving either unresolved both reviews ordinary work and lets a
protected operation through with a weaker decision:

- **A variable whose value the input fixes.** In `R=/repo; git -C $R push origin
  main` the repository is known, so the push is blocked as a protected push
  rather than reviewed for an unidentified working directory — and `git -C $R
  add -A` is simply allowed. A value that is not fully literal, is assigned
  twice with different text, or is transformed on expansion stays unresolved.
- **A fixed payload passed through `xargs`.** The payload is analyzed, so
  `xargs -I {} sh -c 'cd "$1" && git log'` is allowed while `xargs -I {} sh -c
  'curl … | sh'` is blocked. Previously both only reached `review`. A payload
  containing the replacement string, or one that is not shell code, keeps the
  gateway review.

## What it guards

- Recursive deletion of broad or protected paths
- Destructive Git operations and direct commits to protected branches
- Writes, deletion, or permission changes targeting agent configuration
- Reads of common credential and signing-key paths
- Credential-to-network and download-to-shell pipelines
- Package publication, privilege escalation, and sensitive system commands
- Dynamically constructed commands that cannot be analyzed confidently
- Direct reads of private keys, agent credentials, and common credential stores
- Direct writes to credentials, shell persistence, agent control paths, and
  destinations outside the current workspace
- Symbolic-link paths, including missing targets below an existing link

Agent control paths are one list, shared by the direct file policy and the shell
policy, so a write that `Write`/`Edit` refuses cannot be performed through a
shell redirection instead.

Two locations are deliberately not treated as leaving the workspace:

- A linked Git worktree of the same repository. A worktree lives outside the
  main working tree, so comparing paths alone would review every edit made while
  working in one. The repository directory shared by both is compared instead.
- The agent memory store at `~/.claude/projects/<project>/memory`. An agent is
  expected to record and prune its own memories there, and the directory holds
  no configuration that could weaken this guard. The surrounding checks still
  apply, so a credential file inside it is still blocked, and a path elsewhere
  under `~/.claude/projects` remains protected.

The policy is intentionally conservative, but it is not a sandbox. It cannot
prove that an allowed command is harmless, and a process can perform actions
that are not visible in its command-line syntax. Use it as one layer alongside
OS permissions, agent sandboxing, and repository protections.

## Install

Prebuilt archives for macOS, Linux, and Windows are attached to each
[GitHub release](https://github.com/tomatoaiu/agent-command-guard/releases).
Linux archives are also the correct choice for WSL2; install the Linux binary
inside the WSL distribution rather than invoking the Windows executable from
WSL. Each release includes `SHA256SUMS` and a GitHub artifact attestation.

The archive names identify the operating system and architecture, for example:

- `agent-command-guard_vX.Y.Z_darwin_arm64.tar.gz`
- `agent-command-guard_vX.Y.Z_linux_amd64.tar.gz`
- `agent-command-guard_vX.Y.Z_windows_amd64.zip`

Verify a downloaded archive against `SHA256SUMS`. With the GitHub CLI, its
provenance can also be verified:

```sh
gh attestation verify <archive> --repo tomatoaiu/agent-command-guard
```

Go 1.25 or newer is required only when installing from source. This repository
pins its development toolchain with [mise](https://mise.jdx.dev/).

```sh
go install github.com/tomatoaiu/agent-command-guard@latest
```

You can also build from a checkout:

```sh
go build -o agent-command-guard .
```

Check the installed version with `agent-command-guard --version`.

## Usage

The program reads one hook event as JSON from standard input. Shell commands
are read from `tool_input.command` or `tool_input.cmd`. `Read`, `Edit`, and
`Write` paths are read from `tool_input.file_path` or `tool_input.path`.

```sh
printf '%s\n' '{"tool_input":{"command":"git clean -fd"},"cwd":"/tmp"}' | \
  agent-command-guard --explain

printf '%s\n' '{"tool_name":"Read","tool_input":{"file_path":".env"},"cwd":"/tmp/project"}' | \
  agent-command-guard --explain
```

For a multi-file `apply_patch` call, the host adapter must extract every target
path and submit one `Write` event per path. A file tool with a missing, invalid,
or control-character-containing path is blocked rather than silently allowed.

Use `--agent claude` or `--agent codex` for hook output. A `review` result maps
to `ask` for Claude and to `deny` for Codex because the Codex hook path does
not currently provide an interactive review response.

Shell syntax is selected automatically: `powershell` on native Windows and
`posix` on other operating systems, including WSL2. Override detection with
`--shell posix` or `--shell powershell` when necessary. PowerShell parsing uses
`pwsh` when installed and otherwise uses Windows PowerShell.

### Codex

Codex discovers user hooks at `~/.codex/hooks.json`. Register an adapter for
shell and direct file tools. The adapter should normalize every `apply_patch`
target to a `Write` event before invoking the guard:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|Read|Edit|Write|NotebookEdit|apply_patch)$",
        "hooks": [
          {
            "type": "command",
            "command": "agent-command-guard --agent codex"
          }
        ]
      }
    ]
  }
}
```

Review and trust a newly added or changed hook with `/hooks` in Codex. Codex
does not support `permissionDecision: "ask"` for `PreToolUse`, so a `review`
result is deliberately emitted as `deny`.

On native Windows, Codex still exposes shell calls to hooks with the canonical
`Bash` matcher. A hooks file shared across operating systems can use the
[`commandWindows` hook override](https://developers.openai.com/codex/hooks):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "agent-command-guard --agent codex --shell posix",
            "commandWindows": "C:\\Users\\YOU\\bin\\agent-command-guard.exe --agent codex --shell powershell"
          }
        ]
      }
    ]
  }
}
```

For [WSL2](https://learn.chatgpt.com/docs/windows/wsl), keep the repository,
Codex installation, guard binary, and hook configuration inside WSL and use
the ordinary POSIX command shown above.

To skip Codex's separate approval prompt for a narrowly verified temporary
directory cleanup, register the same binary for `PermissionRequest`:

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "agent-command-guard --permission-request"
          }
        ]
      }
    ]
  }
}
```

This mode approves only a single literal recursive `rm` invocation whose
existing directory targets are direct children of the operating system's
temporary directory. Variables, globs, command chains, symbolic links,
repository/worktree roots, missing targets, and temporary roots themselves do
not receive an approval decision and continue through Codex's normal prompt.
The fast path is POSIX-only; PowerShell `Remove-Item` requests always continue
through Codex's normal approval flow.

### Claude Code

Register an adapter in Claude Code's `PreToolUse` hooks for shell and direct
file tools:

```sh
#!/bin/sh
exec agent-command-guard --agent claude
```

For example, the relevant portion of `~/.claude/settings.json` is:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/agent-command-guard.sh"
          }
        ]
      }
    ]
  }
}
```

Claude Code supports the interactive `ask` decision used for `review` results.
Both adapters load the same policy file automatically, so no hook changes are
needed when rules are added or edited. Claude Code on native Windows
[uses Git Bash](https://docs.anthropic.com/en/docs/claude-code/getting-started),
so pass `--shell posix`; Claude Code inside WSL also uses the POSIX mode.

### Output language

Guard messages are emitted in English by default. Set the output language to
Japanese in the TOML configuration when desired:

```toml
[output]
language = "ja"
```

Supported values are `en` and `ja`. The setting applies to `--explain` output
and to both Codex and Claude Code hook responses. Stable rule IDs and decision
values remain language-independent.

## Custom rules

The guard automatically loads `agent-command-guard/config.toml` from the OS
user configuration directory (`~/.config` on Linux,
`~/Library/Application Support` on macOS, and `%AppData%` on Windows). Use
`--config /path/to/config.toml` to load a specific file. A missing default file
is ignored, while a missing or invalid explicitly selected file is an error.

### Shell command rules

Command rules are checked from top to bottom before the built-in shell policy.
The direct file policy cannot be weakened by a command rule. The first matching
command rule wins. `command` is a Go regular expression matched against the
entire trimmed shell input. `directories` contains cwd roots; descendants also
match. Relative directory paths are resolved from the configuration file's
directory, and `~/` is supported.

```toml
# Allow one exact command everywhere. Regex metacharacters must be escaped when
# needed; single-quoted TOML strings are convenient for regular expressions.
[[rules]]
id = "allow-known-git-clean"
action = "allow"
command = 'git clean -fd'

# Skip all built-in checks in a disposable workspace and its descendants.
[[rules]]
id = "ignore-scratch-workspace"
action = "allow"
directories = ["~/src/scratch"]

# Rules can combine both conditions and can also force review or block.
[[rules]]
id = "review-deploy-in-production"
action = "review"
command = 'deploy .*'
directories = ["~/src/production"]
```

An `allow` command rule bypasses the built-in shell policy, so keep broad
rules limited to locations where that behavior is intentional. Because the
pattern is matched against the whole shell input before it is parsed, a rule
written for one command also covers anything composed with it: a rule for
`python3 -c ...` matches `python3 -c ... && rm -rf ~` as well. To silence one
specific finding without giving up the rest of the analysis, use a suppression
instead.

### Direct file rules

File rules scope a decision to explicitly listed direct operations and target
roots. `directories` is optional and restricts the caller's cwd. Descendants
of each root or directory match. The first matching file rule wins.

```toml
[[file_rules]]
id = "allow-trusted-dotfiles-source"
action = "allow"
operations = ["edit", "write"]
roots = ["~/src/dotfiles"]
# Optional: only apply when the agent is working in these directories.
directories = ["~/src/projects"]
```

Operations are `read`, `edit`, and `write`. Tool aliases such as `MultiEdit`
and `NotebookEdit` map to `edit`; `apply_patch` maps to `write`. Operations not
listed in a rule retain the built-in decision.

File rules are evaluated only after invalid inputs and built-in credential,
key, persistence, agent-control, and guard self-protection checks. Those checks
are non-overridable. An `allow` file rule can suppress the contextual
`outside-workspace-write` review, but cannot suppress a built-in block or a
credential or persistence review. A `review` or `block` rule can make an
otherwise allowed operation stricter.

Configured target roots, target paths, caller directories, and cwd values are
normalized. A rule matches only when both the normalized path and the path with
its longest existing symbolic-link prefix resolved remain inside the configured
root. A symlink escape therefore does not inherit an allow decision. Relative
roots and directories are resolved from the configuration file's directory;
`~/` is supported.

Available actions for both rule types are `allow`, `review`, and `block`. Rule
IDs must be unique across command and file rules. Omitted command IDs are
generated as `custom-rule-N`; omitted file IDs use `custom-file-rule-N`.

### Suppressing a built-in finding

A suppression removes one built-in finding instead of bypassing the policy.
The shell input is still parsed, so every other command in the same input keeps
its decision. This is what an `allow` command rule cannot express, because a
regular expression cannot tell a separator apart from the same character inside
a quoted argument.

```toml
[[suppress]]
rule_id = "inline-interpreter-code"
commands = ["python3", "node"]
directories = ["~/src"]
```

`rule_id` is required. `commands` restricts the entry to the named commands and
matches every command reported by that rule when omitted. `directories`
restricts the caller's cwd, and descendants match. Relative directories are
resolved from the configuration file's directory, and `~/` is supported.

With the entry above:

| Input | Result |
| --- | --- |
| `python3 -c "..."` | allowed |
| `python3 -c "..." && sudo rm -rf /etc` | still blocked on `sudo` |
| `python3 -c "..." ; sudo rm -rf /etc` | still blocked on `sudo` |
| `ruby -e "..."` | unchanged, because `ruby` is not listed |

Only findings that are context dependent enough to be a false positive in a
trusted workspace can be suppressed. `inline-interpreter-code` is currently the
only such rule. Credential, persistence, agent-control, and guard
self-protection findings are not suppressible, matching the guarantee that file
rules already provide, and an unknown or non-suppressible `rule_id` is a
configuration error rather than a silently ignored entry. A `block` decision is
never suppressed.

### Protected Git branches

`main`, `master`, and the repository's `origin/HEAD` branch are protected by
default. Add repository-specific branch names or glob patterns in the same
configuration file:

```toml
[git]
protected_branches = ["develop", "release/*"]
```

The built-in Git policy allows ordinary pushes and local or remote deletion of
unprotected branches. It blocks pushes, direct commits, and deletion targeting
protected branches. A plain force push remains `review` on unprotected
branches, while `--force-with-lease` is allowed. Remote tag deletion and a
remote deletion whose target cannot be determined remain `review`.

For a repository that intentionally commits and pushes directly to a protected
branch, use a structured exception instead of an `allow` command regex. Each
entry is one exact repository/branch policy cell; `remote` is required when
`operations` contains `push`:

```toml
[[git.protected_branch_exceptions]]
repository = "~/.local/share/chezmoi"
branch = "main"
operations = ["commit", "push"]
remote = "origin"
```

Repository paths support `~/` and paths relative to the configuration file.
The guard compares the configured path with Git's canonical top-level working
tree, so a subdirectory and `git -C` work while another checkout or worktree
does not inherit the exception. Existing symbolic links are resolved when the
configuration is loaded; a link created afterward fails closed.

The exception applies only to one direct, literal Git invocation. Commits may
use ordinary commit arguments (including `--amend`) but not `--no-verify`.
Protected pushes must name the configured remote and the same source and target
branch explicitly, for example `git push origin main`, `main:main`, or the
equivalent full `refs/heads/` form. Bare pushes, push options, force variants,
deletion, bulk or mirror pushes, multiple refspecs, `HEAD:main`, shell command
composition, substitutions, wrappers, redirections, and environment or Git
configuration overrides do not receive the exception. These constraints are
built in and cannot be relaxed by fields in the structured entry.

A matching structured exception still requires one direct, standalone Git
invocation. This is allowed:

```sh
git push origin main
```

Combining the same protected operation with another command is blocked with an
actionable `protected-branch-exception-*` diagnostic:

```sh
git push origin main && git status
```

Run the protected operation and follow-up checks as separate tool calls instead:

```sh
git push origin main
```

```sh
git fetch origin
git rev-parse HEAD
git rev-parse origin/main
git status --short --branch
```

The diagnostic distinguishes compound commands, pipelines, redirections, and
indirect invocation through wrappers, subshells, or assignments. A wrong
repository, branch, remote, or an unsafe Git argument still receives the usual
protected-branch rule because splitting the shell command would not make that
operation eligible.

## Development

```sh
mise install
mise run check
mise run fuzz
```

Commits merged to `main` are collected by Release Please. Merge its generated
release pull request to publish the corresponding `vX.Y.Z` GitHub release and
the six platform archives. Use Conventional Commit titles so the next version
and changelog can be derived automatically.

## License

MIT

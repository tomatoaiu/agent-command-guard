# agent-command-guard

An AST-based `PreToolUse` guard for shell commands proposed by coding agents.

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

## What it guards

- Recursive deletion of broad or protected paths
- Destructive Git operations and direct commits to protected branches
- Writes, deletion, or permission changes targeting agent configuration
- Reads of common credential and signing-key paths
- Credential-to-network and download-to-shell pipelines
- Package publication, privilege escalation, and sensitive system commands
- Dynamically constructed commands that cannot be analyzed confidently

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

The program reads one hook event as JSON from standard input. The command is
read from `tool_input.command` or `tool_input.cmd`.

```sh
printf '%s\n' '{"tool_input":{"command":"git clean -fd"},"cwd":"/tmp"}' | \
  agent-command-guard --explain
```

Use `--agent claude` or `--agent codex` for hook output. A `review` result maps
to `ask` for Claude and to `deny` for Codex because the Codex hook path does
not currently provide an interactive review response.

Shell syntax is selected automatically: `powershell` on native Windows and
`posix` on other operating systems, including WSL2. Override detection with
`--shell posix` or `--shell powershell` when necessary. PowerShell parsing uses
`pwsh` when installed and otherwise uses Windows PowerShell.

### Codex

Codex discovers user hooks at `~/.codex/hooks.json`. Register the binary for
the `Bash` tool:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
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

Register an adapter in Claude Code's `PreToolUse` hooks for `Bash`:

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
        "matcher": "Bash",
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
Both adapters load the same custom rule file automatically, so no hook changes
are needed when rules are added or edited. Claude Code on native Windows
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

Rules are checked from top to bottom before the built-in policy. The first
matching rule wins. `command` is a Go regular expression matched against the
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

Available actions are `allow`, `review`, and `block`. An `allow` rule bypasses
the built-in policy, so keep broad directory rules limited to locations where
that behavior is intentional. Rule IDs must be unique; omitted IDs are
generated as `custom-rule-N`.

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

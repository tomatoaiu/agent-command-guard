# agent-command-guard

An AST-based `PreToolUse` guard for shell commands proposed by coding agents.

It parses shell input with [`mvdan.cc/sh`](https://github.com/mvdan/sh), walks
commands and redirections (including pipelines, subshells, command
substitutions, and literal nested-shell payloads), and returns one of three
decisions:

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

Go 1.25 or newer is required. This repository pins its development toolchain
with [mise](https://mise.jdx.dev/).

```sh
go install github.com/tomatoaiu/agent-command-guard@latest
```

You can also build from a checkout:

```sh
go build -o agent-command-guard .
```

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
are needed when rules are added or edited.

## Custom rules

The guard automatically loads `agent-command-guard/config.toml` from the OS
user configuration directory (`~/.config` on Linux and
`~/Library/Application Support` on macOS). Use
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

## License

MIT

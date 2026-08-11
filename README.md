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

Example adapter:

```sh
#!/bin/sh
exec agent-command-guard --agent claude
```

Register that adapter as a `PreToolUse` hook for shell tool calls using your
agent's supported configuration format.

## Development

```sh
mise install
mise run check
mise run fuzz
```

## License

MIT

package main

import (
	"os"
	"path/filepath"
)

// Entries under ~/.claude that decide what the agent does: what it is told, what
// it may run, and what runs on its behalf. The directory also holds runtime data
// — transcripts, todos, per-project scratch space — which the agent writes as
// part of doing its job and which grants an attacker nothing, so the control
// surface is named rather than taking the directory whole.
//
// Taking it whole is what forced a carve-out for the memory store, and every
// skill that keeps working files under ~/.claude would have needed another one.
var claudeControlEntries = []string{
	"CLAUDE.md",
	"agents",
	"commands",
	"hooks",
	"keybindings.json",
	"mcp.json",
	"output-styles",
	"plugins",
	"settings.json",
	"settings.local.json",
	"skills",
}

// agentControlRoots returns the paths holding agent configuration, hooks,
// skills, and the guard itself. An agent must not rewrite its own controls, so
// the direct file policy and the shell policy both consult this list. A single
// definition keeps the two in step: a write that Write/Edit blocks cannot be
// performed through a shell redirection instead.
//
// ~/.codex, ~/.pi/agent, and ~/.agents are taken whole. Their layouts are not
// known well enough here to name a control surface inside them, and narrowing a
// protection on a guess would open a hole rather than close a false positive.
func agentControlRoots(home string) []string {
	roots := []string{
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".pi", "agent"),
		filepath.Join(home, ".agents"),
		// Not inside ~/.claude: it carries the user-scope MCP server
		// definitions, and each of those is a command the agent runs.
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".local", "bin", "agent-command-guard"),
	}
	for _, entry := range claudeControlEntries {
		roots = append(roots, filepath.Join(home, ".claude", entry))
	}
	if configPath, err := DefaultConfigPath(); err == nil {
		roots = append(roots, configPath)
	}
	if executable, err := os.Executable(); err == nil {
		roots = append(roots, executable)
	}
	return roots
}

// agentRuntimePath reports whether path sits in the agent's own runtime area:
// anywhere under ~/.claude that is not part of the control surface. Transcripts,
// todos, memories, and whatever working files a skill keeps there are all
// written by the agent as it works, so a write landing there is expected rather
// than worth reviewing for leaving the workspace.
//
// Defining it as the complement of the control surface is what stops this from
// becoming a list of exceptions that grows once per skill.
func agentRuntimePath(path, home string) bool {
	if home == "" {
		return false
	}
	claude := filepath.Join(home, ".claude")
	if !pathWithin(path, claude) && !pathWithin(path, resolvePathSymlinks(claude)) {
		return false
	}
	for _, entry := range claudeControlEntries {
		root := filepath.Join(claude, entry)
		if pathWithin(path, root) || pathWithin(path, resolvePathSymlinks(root)) {
			return false
		}
	}
	return true
}

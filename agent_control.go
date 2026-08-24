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
//
// Skills are deliberately absent: see agentSkillRoots.
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
}

// agentSkillRoots returns the user-scope skill trees an agent is expected to
// author and revise. They sit inside otherwise-protected trees, so both the
// direct file policy and the shell policy check them before the control roots
// and let the write through.
//
// Skills are model instructions, so a write here can change how the agent
// behaves on a later turn. They are excluded anyway because authoring them is
// ordinary work, and the project-scope equivalent — .claude/skills inside a
// repository — was never protected, so blocking only the user-scope copy bought
// no protection while breaking a normal edit. What decides which commands run —
// hooks, settings, MCP definitions, commands, subagents — stays protected.
func agentSkillRoots(home string) []string {
	if home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".claude", "skills"),
		filepath.Join(home, ".agents", "skills"),
	}
}

// agentSkillWrite reports whether a write targets a skill tree. It requires the
// path to sit inside one both lexically and after resolving symlinks, so a link
// planted inside a skill directory cannot reach the rest of the control surface
// through this exception.
func agentSkillWrite(normalized, resolved, home string) bool {
	for _, root := range agentSkillRoots(home) {
		if pathMatchesRoot(normalized, root) && pathMatchesRoot(resolved, root) {
			return true
		}
	}
	return false
}

// agentControlRoots returns the paths holding agent configuration, hooks, and
// the guard itself. An agent must not rewrite its own controls, so the direct
// file policy and the shell policy both consult this list. A single definition
// keeps the two in step: a write that Write/Edit blocks cannot be performed
// through a shell redirection instead.
//
// ~/.codex and ~/.pi/agent are taken whole. Their layouts are not known well
// enough here to name a control surface inside them, and narrowing a protection
// on a guess would open a hole rather than close a false positive. ~/.agents is
// taken whole except for its skill tree, which agentSkillRoots names.
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
// the skill trees, plus anywhere under ~/.claude that is not part of the control
// surface. Transcripts, todos, memories, skills, and whatever working files a
// skill keeps there are all written by the agent as it works, so a write landing
// there is expected rather than worth reviewing for leaving the workspace.
//
// Defining the ~/.claude part as the complement of the control surface is what
// stops this from becoming a list of exceptions that grows once per skill.
// ~/.agents/skills is named because the tree around it stays protected.
func agentRuntimePath(path, home string) bool {
	if home == "" {
		return false
	}
	for _, root := range agentSkillRoots(home) {
		if pathWithin(path, root) || pathWithin(path, resolvePathSymlinks(root)) {
			return true
		}
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

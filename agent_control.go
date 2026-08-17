package main

import (
	"os"
	"path/filepath"
	"strings"
)

// agentControlRoots returns the roots holding agent configuration, hooks,
// skills, and the guard itself. An agent must not rewrite its own controls, so
// the direct file policy and the shell policy both consult this list. A single
// definition keeps the two in step: a write that Write/Edit blocks cannot be
// performed through a shell redirection instead.
func agentControlRoots(home string) []string {
	roots := []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".pi", "agent"),
		filepath.Join(home, ".agents"),
		filepath.Join(home, ".local", "bin", "agent-command-guard"),
	}
	if configPath, err := DefaultConfigPath(); err == nil {
		roots = append(roots, configPath)
	}
	if executable, err := os.Executable(); err == nil {
		roots = append(roots, executable)
	}
	return roots
}

// agentMemoryPath reports whether path sits inside an agent memory store at
// ~/.claude/projects/<project>/memory. An agent is expected to record and prune
// its own memories there, and the directory carries no configuration that could
// weaken this guard, so it is carved out of the agent control roots.
//
// The comparison is deliberately case sensitive. On a case-insensitive volume a
// spelling such as "Memory" reaches the same directory but does not match here,
// which leaves it protected rather than exempt.
// The caller checks the normalized path and its symlink-resolved form
// separately, so each form is compared against the matching form of the
// projects directory. A symlink that leaves the memory store still resolves to
// a protected path and is caught on the resolved pass.
func agentMemoryPath(path, home string) bool {
	if home == "" {
		return false
	}
	projects := filepath.Join(home, ".claude", "projects")
	return underMemoryDirectory(path, projects) ||
		underMemoryDirectory(path, resolvePathSymlinks(projects))
}

func underMemoryDirectory(path, projects string) bool {
	if !pathWithin(path, projects) {
		return false
	}
	relative, err := filepath.Rel(projects, path)
	if err != nil {
		return false
	}
	segments := strings.Split(filepath.ToSlash(relative), "/")
	return len(segments) >= 2 && segments[1] == "memory"
}

package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// A linked worktree lives outside the main working tree, so comparing paths
// alone reports every edit inside one as leaving the workspace. Both directions
// must be allowed, while an unrelated repository stays under review.
func TestLinkedWorktreeCountsAsSameWorkspace(t *testing.T) {
	repository := committedRepository(t, "main")
	worktree := filepath.Join(t.TempDir(), "linked")
	command := exec.Command("git", "-C", repository, "worktree", "add", "-b", "feat/worktree", worktree)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git worktree add: %v: %s", err, output)
	}

	tests := []struct {
		name   string
		target string
		cwd    string
	}{
		{"main tree writes into the worktree", filepath.Join(worktree, "src.ts"), repository},
		{"worktree writes into the main tree", filepath.Join(repository, "src.ts"), worktree},
		{"nested path that does not exist yet", filepath.Join(worktree, "src", "nested", "a.ts"), repository},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := AnalyzeFile(FileWrite, test.target, test.cwd, Config{})
			if result.Decision != Allow {
				t.Fatalf("got %s, want allow; findings=%+v", result.Decision, result.Findings)
			}
		})
	}

	unrelated := committedRepository(t, "main")
	result := AnalyzeFile(FileWrite, filepath.Join(unrelated, "src.ts"), repository, Config{})
	if result.Decision != Review || !hasRule(result, "outside-workspace-write") {
		t.Fatalf("unrelated repository: got %s; findings=%+v", result.Decision, result.Findings)
	}
}

// ~/.claude holds the agent's runtime area alongside its control surface. The
// runtime area is written as the agent works and grants an attacker nothing, so
// it must not be protected just because of where it sits.
func TestAgentRuntimeAreaIsWritable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	claude := filepath.Join(home, ".claude")

	paths := []string{
		filepath.Join(claude, "projects", "project", "memory", "note.md"),
		filepath.Join(claude, "projects", "project", "session.jsonl"),
		filepath.Join(claude, "projects", "project", "Memory", "note.md"),
		filepath.Join(claude, "todos", "list.json"),
		filepath.Join(claude, "scratch", "review-deck", "annotations.json"),
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			result := AnalyzeFile(FileWrite, path, workspace, Config{})
			if result.Decision != Allow {
				t.Fatalf("got %s, want allow; findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

func TestAgentMemoryStoreIsWritable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	memory := filepath.Join(home, ".claude", "projects", "project", "memory")

	for _, operation := range []FileOperation{FileWrite, FileEdit} {
		t.Run(string(operation), func(t *testing.T) {
			result := AnalyzeFile(operation, filepath.Join(memory, "note.md"), workspace, Config{})
			if result.Decision != Allow {
				t.Fatalf("got %s, want allow; findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

// Leaving the runtime area writable must not weaken the control surface beside
// it, nor the credential checks that apply everywhere.
func TestAgentControlSurfaceStaysProtected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	claude := filepath.Join(home, ".claude")

	tests := []struct {
		name string
		path string
	}{
		{"credential file inside the runtime area", filepath.Join(claude, "projects", "project", "memory", ".env")},
		{"skills", filepath.Join(claude, "skills", "daily", "SKILL.md")},
		{"settings", filepath.Join(claude, "settings.json")},
		{"local settings", filepath.Join(claude, "settings.local.json")},
		{"instructions", filepath.Join(claude, "CLAUDE.md")},
		{"hooks", filepath.Join(claude, "hooks", "guard.sh")},
		{"agents", filepath.Join(claude, "agents", "reviewer.md")},
		{"commands", filepath.Join(claude, "commands", "deploy.md")},
		{"plugins", filepath.Join(claude, "plugins", "example", "index.js")},
		{"output styles", filepath.Join(claude, "output-styles", "terse.md")},
		// Outside ~/.claude, and it defines the MCP servers the agent runs.
		{"user scope state", filepath.Join(home, ".claude.json")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := AnalyzeFile(FileWrite, test.path, workspace, Config{})
			if result.Decision != Block || !hasRule(result, "sensitive-file-write") {
				t.Fatalf("got %s, want block; findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

// The shell policy and the direct file policy share one definition of the agent
// control roots, so a redirection cannot reach what Write/Edit refuses.
func TestShellRedirectionMatchesFilePolicyForAgentControl(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()

	blocked := []struct {
		name string
		path string
	}{
		{"skills", filepath.Join(home, ".claude", "skills", "daily", "SKILL.md")},
		{"settings", filepath.Join(home, ".claude", "settings.json")},
		{"agents", filepath.Join(home, ".claude", "agents", "reviewer.md")},
		{"codex config", filepath.Join(home, ".codex", "config.toml")},
	}
	for _, test := range blocked {
		t.Run(test.name, func(t *testing.T) {
			command := "echo x > " + test.path
			result := analyzePOSIXWithConfig(command, workspace, Config{})
			if result.Decision != Block {
				t.Fatalf("got %s, want block; findings=%+v", result.Decision, result.Findings)
			}
			direct := AnalyzeFile(FileWrite, test.path, workspace, Config{})
			if direct.Decision != Block {
				t.Fatalf("direct write disagrees with the shell policy: got %s", direct.Decision)
			}
		})
	}

	memory := filepath.Join(home, ".claude", "projects", "project", "memory", "note.md")
	result := analyzePOSIXWithConfig("echo x > "+memory, workspace, Config{})
	if result.Decision != Allow {
		t.Fatalf("memory store: got %s, want allow; findings=%+v", result.Decision, result.Findings)
	}
}

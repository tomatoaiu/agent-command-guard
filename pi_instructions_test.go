package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPiInstructionsAreWritable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	target := filepath.Join(home, ".pi", "agent", "AGENTS.md")

	assertPiInstructionDecision(t, target, workspace, Config{}, Allow)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("# Instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertPiInstructionDecision(t, target, workspace, Config{}, Allow)

	// A site may still forbid edits explicitly; this is not a policy bypass.
	config := Config{FileRules: []FileRule{{
		ID: "block-instructions", Action: Block,
		Operations: []FileOperation{FileEdit, FileWrite}, Roots: []string{target},
	}}}
	if err := config.prepare(home); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []FileOperation{FileEdit, FileWrite} {
		result := AnalyzeFile(operation, target, workspace, config)
		if result.Decision != Block || !hasRule(result, "block-instructions") {
			t.Fatalf("explicit policy: got %+v", result)
		}
	}

	// Trusting a script makes that file immutable even if it has this name.
	config = Config{MacOS: MacOSConfig{TrustedOSAScriptFiles: []string{target}}}
	if err := config.prepare(home); err != nil {
		t.Fatal(err)
	}
	assertPiInstructionDecision(t, target, workspace, config, Block)
}

func TestPiInstructionsDoNotUnprotectOtherPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	paths := []string{
		filepath.Join(".pi", "agent"),
		filepath.Join(".pi", "agent", "AGENTS.md.bak"),
		filepath.Join(".pi", "agent", "AGENTS.md", "nested.md"),
		filepath.Join(".pi", "agent", "nested", "AGENTS.md"),
		filepath.Join(".pi", "agent", "settings.json"),
		filepath.Join(".pi", "agent", "auth.json"),
		filepath.Join(".pi", "agent", "hooks", "guard.sh"),
		filepath.Join(".pi", "agent", "extensions", "guard.ts"),
		filepath.Join(".pi", "agent", "agents", "reviewer.md"),
		filepath.Join(".codex", "AGENTS.md"),
		filepath.Join(".claude", "CLAUDE.md"),
		filepath.Join(".local", "bin", "agent-command-guard"),
	}
	for _, path := range paths {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			assertPiInstructionDecision(t, filepath.Join(home, path), workspace, Config{}, Block)
		})
	}
	guardConfig, err := DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	assertPiInstructionDecision(t, guardConfig, workspace, Config{}, Block)

	// The exact name is a file exception, never a directory exception.
	target := filepath.Join(home, ".pi", "agent", "AGENTS.md")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	assertPiInstructionDecision(t, target, workspace, Config{}, Block)
}

func TestPiInstructionsRejectSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	for _, test := range []struct {
		name     string
		link     string
		dangling bool
	}{
		{"file", filepath.Join(".pi", "agent", "AGENTS.md"), false},
		{"dangling file", filepath.Join(".pi", "agent", "AGENTS.md"), true},
		{"agent directory", filepath.Join(".pi", "agent"), false},
		{"dangling agent directory", filepath.Join(".pi", "agent"), true},
		{"pi directory", ".pi", false},
		{"dangling pi directory", ".pi", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			workspace := t.TempDir()
			link := filepath.Join(home, test.link)
			destination := filepath.Join(home, ".codex", "missing")
			if !test.dangling {
				if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
					t.Fatal(err)
				}
				if filepath.Base(link) == "AGENTS.md" {
					if err := os.WriteFile(destination, []byte("protected\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.MkdirAll(destination, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(destination, link); err != nil {
				t.Fatal(err)
			}
			assertPiInstructionDecision(t, filepath.Join(home, ".pi", "agent", "AGENTS.md"), workspace, Config{}, Block)
		})
	}
}

func TestPiInstructionsDoNotUnprotectAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	target := filepath.Join(home, ".pi", "agent", "AGENTS.md")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("# Instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, ".pi", "agent", "settings.json")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	assertPiInstructionDecision(t, alias, workspace, Config{}, Block)
}

func TestPiInstructionsWithSymlinkedHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(t.TempDir(), home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	assertPiInstructionDecision(t, filepath.Join(home, ".pi", "agent", "AGENTS.md"), t.TempDir(), Config{}, Allow)
}

func TestPiInstructionsKeepNonWriteProtection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	path := "'" + filepath.Join(home, ".pi", "agent", "AGENTS.md") + "'"
	for _, command := range []string{
		"rm " + path,
		"rm -rf " + path,
		"unlink " + path,
		"chmod 600 " + path,
		"chown user " + path,
		"ln -s " + path + " alias",
	} {
		result := analyzePOSIXWithConfig(command, workspace, Config{})
		if result.Decision != Block {
			t.Errorf("%s: got %+v, want block", command, result)
		}
	}
}

func TestPiInstructionsPowerShell(t *testing.T) {
	if _, err := findPowerShell(); err != nil {
		if runtime.GOOS == "windows" {
			t.Fatal(err)
		}
		t.Skip("PowerShell is not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	for _, test := range []struct {
		name     string
		decision Decision
	}{
		{"AGENTS.md", Allow},
		{"settings.json", Block},
		{"auth.json", Block},
		{"AGENTS.md.bak", Block},
	} {
		path := quotePowerShell(filepath.Join(home, ".pi", "agent", test.name))
		for _, command := range []string{
			"Write-Output x > " + path,
			"Set-Content -Path " + path + " -Value x",
			"Copy-Item source -Destination " + path,
		} {
			result := AnalyzeWithConfigAndShell(command, workspace, Config{}, ShellPowerShell)
			if result.Decision != test.decision {
				t.Errorf("%s: got %+v, want %s", command, result, test.decision)
			}
		}
	}
}

func TestPiInstructionsPowerShellKeepsNonWriteProtection(t *testing.T) {
	if _, err := findPowerShell(); err != nil {
		if runtime.GOOS == "windows" {
			t.Fatal(err)
		}
		t.Skip("PowerShell is not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := t.TempDir()
	path := quotePowerShell(filepath.Join(home, ".pi", "agent", "AGENTS.md"))
	for _, command := range []string{
		"Remove-Item " + path,
		"Set-Acl -Path " + path + " -AclObject $acl",
		"New-Item -ItemType SymbolicLink -Path " + path + " -Value missing",
	} {
		result := AnalyzeWithConfigAndShell(command, workspace, Config{}, ShellPowerShell)
		if result.Decision != Block {
			t.Errorf("%s: got %+v, want block", command, result)
		}
	}
}

func assertPiInstructionDecision(t *testing.T, target, cwd string, config Config, want Decision) {
	t.Helper()
	for _, operation := range []FileOperation{FileEdit, FileWrite} {
		result := AnalyzeFile(operation, target, cwd, config)
		if result.Decision != want || want == Block && !hasRule(result, "sensitive-file-write") {
			t.Errorf("%s %s: got %+v, want %s", operation, target, result, want)
		}
	}
	quoted := "'" + strings.ReplaceAll(target, "'", "'\\''") + "'"
	for _, command := range []string{"printf x > " + quoted, "printf x >> " + quoted, "tee " + quoted} {
		result := analyzePOSIXWithConfig(command, cwd, config)
		if result.Decision != want {
			t.Errorf("%s: got %+v, want %s", command, result, want)
		}
	}
}

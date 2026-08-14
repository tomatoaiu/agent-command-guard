package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAnalyzeFilePolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, "work", "project")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		operation FileOperation
		path      string
		decision  Decision
		rule      string
	}{
		{"ordinary read", FileRead, "README.md", Allow, ""},
		{"ordinary write", FileWrite, "src/main.go", Allow, ""},
		{"dotenv read", FileRead, ".env.local", Review, "sensitive-file-read-review"},
		{"dotenv template read", FileRead, ".env.example", Allow, ""},
		{"dotenv write", FileWrite, ".env.production", Block, "sensitive-file-write"},
		{"private key read", FileRead, "fixtures/id_ed25519", Block, "sensitive-file-read"},
		{"private key extension read", FileRead, "fixtures/client.pem", Block, "sensitive-file-read"},
		{"dotenv decryption key read", FileRead, "secrets/.env.keys", Block, "sensitive-file-read"},
		{"credential file read", FileRead, "service-account-prod.json", Block, "sensitive-file-read"},
		{"credential config read", FileRead, ".npmrc", Review, "sensitive-file-read-review"},
		{"zsh profile write", FileWrite, ".zshrc", Review, "shell-profile-write"},
		{"bash profile write", FileWrite, ".bashrc", Block, "sensitive-file-write"},
		{"secrets directory write", FileWrite, "config/secrets/value.txt", Block, "sensitive-file-write"},
		{"directory boundary", FileWrite, "config/secretsauce/value.txt", Allow, ""},
		{"agent auth read", FileRead, filepath.Join(home, ".codex", "auth.json"), Block, "sensitive-file-read"},
		{"agent config write", FileWrite, filepath.Join(home, ".pi", "agent", "settings.json"), Block, "sensitive-file-write"},
		{"ordinary outside read", FileRead, filepath.Join(home, "Downloads", "notes.txt"), Allow, ""},
		{"ordinary outside write", FileWrite, filepath.Join(home, "Downloads", "notes.txt"), Review, "outside-workspace-write"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := AnalyzeFile(test.operation, test.path, workspace, Config{})
			if result.Decision != test.decision {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
			if test.rule != "" && !hasRule(result, test.rule) {
				t.Fatalf("missing rule %q in %+v", test.rule, result.Findings)
			}
		})
	}
}

func TestAnalyzeFileRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation FileOperation
		path      string
		rule      string
	}{
		{"empty", FileRead, "", "invalid-file-path"},
		{"stdin marker", FileRead, "-", "invalid-file-path"},
		{"nul", FileWrite, "safe\x00.env", "invalid-file-path"},
		{"newline", FileWrite, "safe\nfile.txt", "invalid-file-path"},
		{"oversized", FileWrite, strings.Repeat("a", maxToolPathBytes+1), "invalid-file-path"},
		{"operation", FileOperation("delete"), "file.txt", "invalid-file-operation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := AnalyzeFile(test.operation, test.path, t.TempDir(), Config{})
			if result.Decision != Block || !hasRule(result, test.rule) {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

func TestAnalyzeFileResolvesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	workspace := filepath.Join(home, "project")
	outside := filepath.Join(home, "outside")
	protected := filepath.Join(home, ".pi", "agent")
	for _, directory := range []string{workspace, outside, protected} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	outsideLink := filepath.Join(workspace, "outside-link")
	if err := os.Symlink(outside, outsideLink); err != nil {
		t.Fatal(err)
	}
	result := AnalyzeFile(FileWrite, filepath.Join(outsideLink, "new.txt"), workspace, Config{})
	if result.Decision != Review || !hasRule(result, "outside-workspace-write") {
		t.Fatalf("outside symlink: got decision=%s findings=%+v", result.Decision, result.Findings)
	}

	protectedLink := filepath.Join(workspace, "agent-link")
	if err := os.Symlink(protected, protectedLink); err != nil {
		t.Fatal(err)
	}
	result = AnalyzeFile(FileWrite, filepath.Join(protectedLink, "not-created.ts"), workspace, Config{})
	if result.Decision != Block || !hasRule(result, "sensitive-file-write") {
		t.Fatalf("protected missing target: got decision=%s findings=%+v", result.Decision, result.Findings)
	}

	secret := filepath.Join(outside, ".env")
	if err := os.WriteFile(secret, []byte("TOKEN=test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretLink := filepath.Join(workspace, "public-name")
	if err := os.Symlink(secret, secretLink); err != nil {
		t.Fatal(err)
	}
	result = AnalyzeFile(FileRead, secretLink, workspace, Config{})
	if result.Decision != Review || !hasRule(result, "sensitive-file-read-review") {
		t.Fatalf("secret symlink: got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestAnalyzeHookInputDispatchesFileTools(t *testing.T) {
	workspace := t.TempDir()
	for _, toolName := range []string{"Read", "read", "view", "open", "read_file"} {
		result := analyzeHookInput(hookInput{
			ToolName:  toolName,
			ToolInput: map[string]any{"path": ".env"},
			CWD:       workspace,
		}, Config{}, ShellPOSIX)
		if result.Decision != Review {
			t.Errorf("%s: got decision=%s findings=%+v", toolName, result.Decision, result.Findings)
		}
	}
	for _, toolName := range []string{"Edit", "write", "write_file", "apply_patch", "MultiEdit", "NotebookEdit"} {
		result := analyzeHookInput(hookInput{
			ToolName:  toolName,
			ToolInput: map[string]any{"file_path": ".env", "notebook_path": ".env"},
			CWD:       workspace,
		}, Config{}, ShellPOSIX)
		if result.Decision != Block {
			t.Errorf("%s: got decision=%s findings=%+v", toolName, result.Decision, result.Findings)
		}
	}

	missingPath := analyzeHookInput(hookInput{ToolName: "Read", ToolInput: map[string]any{}, CWD: workspace}, Config{}, ShellPOSIX)
	if missingPath.Decision != Block || !hasRule(missingPath, "invalid-file-path") {
		t.Fatalf("missing path: got decision=%s findings=%+v", missingPath.Decision, missingPath.Findings)
	}

	shell := analyzeHookInput(hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git reset --hard"},
		CWD:       workspace,
	}, Config{}, ShellPOSIX)
	if shell.Decision != Block || !hasRule(shell, "git-reset-hard") {
		t.Fatalf("shell dispatch: got decision=%s findings=%+v", shell.Decision, shell.Findings)
	}
}

func TestAnalyzeFileRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, "work", "project")
	otherWorkspace := filepath.Join(home, "work", "other")
	trusted := filepath.Join(home, "dotfiles")
	for _, directory := range []string{workspace, otherWorkspace, trusted} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	config := Config{FileRules: []FileRule{{
		ID:          "allow-trusted-dotfiles",
		Action:      Allow,
		Operations:  []FileOperation{FileEdit, FileWrite},
		Roots:       []string{trusted},
		Directories: []string{workspace},
	}}}
	if err := config.prepare(home); err != nil {
		t.Fatal(err)
	}

	for _, operation := range []FileOperation{FileEdit, FileWrite} {
		result := AnalyzeFile(operation, filepath.Join(trusted, "config.toml"), workspace, config)
		if result.Decision != Allow || !hasRule(result, "allow-trusted-dotfiles") {
			t.Errorf("%s: got decision=%s findings=%+v", operation, result.Decision, result.Findings)
		}
	}

	read := AnalyzeFile(FileRead, filepath.Join(trusted, "config.toml"), workspace, config)
	if read.Decision != Allow || hasRule(read, "allow-trusted-dotfiles") {
		t.Fatalf("unlisted read operation inherited rule: decision=%s findings=%+v", read.Decision, read.Findings)
	}

	for name, path := range map[string]string{
		"sibling":          filepath.Join(home, "notes", "config.toml"),
		"prefix collision": filepath.Join(home, "dotfiles-backup", "config.toml"),
	} {
		t.Run(name, func(t *testing.T) {
			result := AnalyzeFile(FileWrite, path, workspace, config)
			if result.Decision != Review || !hasRule(result, "outside-workspace-write") || hasRule(result, "allow-trusted-dotfiles") {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}

	wrongCaller := AnalyzeFile(FileEdit, filepath.Join(trusted, "config.toml"), otherWorkspace, config)
	if wrongCaller.Decision != Review || !hasRule(wrongCaller, "outside-workspace-write") {
		t.Fatalf("caller restriction: got decision=%s findings=%+v", wrongCaller.Decision, wrongCaller.Findings)
	}
}

func TestAnalyzeFileRulePrecedence(t *testing.T) {
	home := t.TempDir()
	workspace := filepath.Join(home, "workspace")
	trusted := filepath.Join(home, "trusted")
	for _, directory := range []string{workspace, trusted} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := Config{FileRules: []FileRule{
		{ID: "review-first", Action: Review, Operations: []FileOperation{FileWrite}, Roots: []string{trusted}},
		{ID: "allow-second", Action: Allow, Operations: []FileOperation{FileWrite}, Roots: []string{trusted}},
	}}
	if err := config.prepare(home); err != nil {
		t.Fatal(err)
	}
	result := AnalyzeFile(FileWrite, filepath.Join(trusted, "config.toml"), workspace, config)
	if result.Decision != Review || !hasRule(result, "review-first") || hasRule(result, "allow-second") {
		t.Fatalf("first match: got decision=%s findings=%+v", result.Decision, result.Findings)
	}

	blockConfig := Config{FileRules: []FileRule{{
		ID: "block-credential-review", Action: Block, Operations: []FileOperation{FileRead}, Roots: []string{trusted},
	}}}
	if err := blockConfig.prepare(home); err != nil {
		t.Fatal(err)
	}
	result = AnalyzeFile(FileRead, filepath.Join(trusted, ".npmrc"), workspace, blockConfig)
	if result.Decision != Block || !hasRule(result, "block-credential-review") {
		t.Fatalf("stricter rule: got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestAnalyzeFileRulesDoNotWeakenBuiltins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, "work")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	config := Config{FileRules: []FileRule{{
		ID:         "allow-home",
		Action:     Allow,
		Operations: []FileOperation{FileRead, FileEdit, FileWrite},
		Roots:      []string{home},
	}}}
	if err := config.prepare(home); err != nil {
		t.Fatal(err)
	}

	guardConfig, err := DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		operation FileOperation
		path      string
		decision  Decision
		rule      string
	}{
		{"agent control write", FileEdit, filepath.Join(home, ".codex", "config.toml"), Block, "sensitive-file-write"},
		{"credential write", FileWrite, filepath.Join(home, ".env.production"), Block, "sensitive-file-write"},
		{"persistence write", FileEdit, filepath.Join(home, ".bashrc"), Block, "sensitive-file-write"},
		{"guard config write", FileWrite, guardConfig, Block, "sensitive-file-write"},
		{"guard binary write", FileWrite, filepath.Join(home, ".local", "bin", "agent-command-guard"), Block, "sensitive-file-write"},
		{"private key read", FileRead, filepath.Join(home, "keys", "id_ed25519"), Block, "sensitive-file-read"},
		{"credential review", FileRead, filepath.Join(home, ".npmrc"), Review, "sensitive-file-read-review"},
		{"persistence review", FileEdit, filepath.Join(home, ".zshrc"), Review, "shell-profile-write"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := AnalyzeFile(test.operation, test.path, workspace, config)
			if result.Decision != test.decision || !hasRule(result, test.rule) || hasRule(result, "allow-home") {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

func TestAnalyzeFileRuleSymlinkContainment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	workspace := filepath.Join(home, "workspace")
	trusted := filepath.Join(home, "trusted")
	outside := filepath.Join(home, "outside")
	for _, directory := range []string{workspace, trusted, outside} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := Config{FileRules: []FileRule{{
		ID:         "allow-trusted",
		Action:     Allow,
		Operations: []FileOperation{FileWrite},
		Roots:      []string{trusted},
	}}}
	if err := config.prepare(home); err != nil {
		t.Fatal(err)
	}

	escape := filepath.Join(trusted, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	result := AnalyzeFile(FileWrite, filepath.Join(escape, "new.txt"), workspace, config)
	if result.Decision != Review || !hasRule(result, "outside-workspace-write") || hasRule(result, "allow-trusted") {
		t.Fatalf("symlink escape: got decision=%s findings=%+v", result.Decision, result.Findings)
	}

	trustedAlias := filepath.Join(home, "trusted-alias")
	if err := os.Symlink(trusted, trustedAlias); err != nil {
		t.Fatal(err)
	}
	aliasConfig := Config{FileRules: []FileRule{{
		ID:         "allow-trusted-alias",
		Action:     Allow,
		Operations: []FileOperation{FileWrite},
		Roots:      []string{trustedAlias},
	}}}
	if err := aliasConfig.prepare(home); err != nil {
		t.Fatal(err)
	}
	result = AnalyzeFile(FileWrite, filepath.Join(trustedAlias, "new.txt"), workspace, aliasConfig)
	if result.Decision != Allow || !hasRule(result, "allow-trusted-alias") {
		t.Fatalf("configured symlink root: got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestFileOperationForTool(t *testing.T) {
	for tool, want := range map[string]FileOperation{
		"Read":         FileRead,
		"read_file":    FileRead,
		"Edit":         FileEdit,
		"MultiEdit":    FileEdit,
		"NotebookEdit": FileEdit,
		"Write":        FileWrite,
		"write_file":   FileWrite,
		"apply_patch":  FileWrite,
	} {
		got, ok := fileOperationForTool(tool)
		if !ok || got != want {
			t.Errorf("%s: got (%q, %t), want (%q, true)", tool, got, ok, want)
		}
	}
	if got, ok := fileOperationForTool("Bash"); ok || got != "" {
		t.Fatalf("Bash: got (%q, %t), want unsupported", got, ok)
	}
}

func TestFileRuleConfigValidation(t *testing.T) {
	validRule := func() FileRule {
		return FileRule{
			ID:         "files",
			Action:     Allow,
			Operations: []FileOperation{FileWrite},
			Roots:      []string{"./trusted"},
		}
	}
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "invalid action",
			config: Config{FileRules: []FileRule{{
				ID: "files", Action: Decision("skip"), Operations: []FileOperation{FileWrite}, Roots: []string{"./trusted"},
			}}},
		},
		{
			name: "missing operations",
			config: Config{FileRules: []FileRule{{
				ID: "files", Action: Allow, Roots: []string{"./trusted"},
			}}},
		},
		{
			name: "invalid operation",
			config: Config{FileRules: []FileRule{{
				ID: "files", Action: Allow, Operations: []FileOperation{"delete"}, Roots: []string{"./trusted"},
			}}},
		},
		{
			name: "duplicate operation",
			config: Config{FileRules: []FileRule{{
				ID: "files", Action: Allow, Operations: []FileOperation{FileWrite, FileWrite}, Roots: []string{"./trusted"},
			}}},
		},
		{
			name: "missing roots",
			config: Config{FileRules: []FileRule{{
				ID: "files", Action: Allow, Operations: []FileOperation{FileWrite},
			}}},
		},
		{
			name: "empty root",
			config: Config{FileRules: []FileRule{{
				ID: "files", Action: Allow, Operations: []FileOperation{FileWrite}, Roots: []string{""},
			}}},
		},
		{
			name: "duplicate command id",
			config: Config{
				Rules:     []Rule{{ID: "files", Action: Allow, Command: "echo ok"}},
				FileRules: []FileRule{validRule()},
			},
		},
		{
			name:   "duplicate file id",
			config: Config{FileRules: []FileRule{validRule(), validRule()}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.config.prepare(t.TempDir()); err == nil {
				t.Fatal("invalid file rule was accepted")
			}
		})
	}
}

func TestAnalyzeFileLocalization(t *testing.T) {
	config := Config{Output: OutputConfig{Language: "ja"}}
	result := AnalyzeFile(FileRead, ".env", t.TempDir(), config)
	if result.Decision != Review || !strings.Contains(result.Message, "読み取り前に確認") {
		t.Fatalf("Japanese message: %q", result.Message)
	}
}

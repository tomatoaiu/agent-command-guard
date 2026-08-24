package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

type FileOperation string

const (
	FileRead  FileOperation = "read"
	FileEdit  FileOperation = "edit"
	FileWrite FileOperation = "write"
)

const maxToolPathBytes = 4096

// AnalyzeFile applies the shared policy for direct file tools. The path is
// checked both lexically and after resolving its longest existing symlink
// prefix, so a not-yet-created file below a symlink cannot bypass the policy.
func AnalyzeFile(operation FileOperation, path, cwd string, config Config) Result {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if absolute, err := filepath.Abs(cwd); err == nil {
		cwd = absolute
	}

	a := &analyzer{
		cwd:      filepath.Clean(cwd),
		home:     userHomeDir(),
		shell:    ShellAuto.resolved(),
		language: config.Output.Language,
	}
	if !validToolPath(path) {
		a.add(Block, "invalid-file-path", string(operation), "")
		return a.result()
	}

	normalized := a.normalizePath(path)
	resolved := resolvePathSymlinks(normalized)
	builtin := analyzeFileBuiltin(operation, normalized, resolved, a)
	if builtin.Decision == Block {
		return builtin
	}

	resolvedCWD := resolvePathSymlinks(a.cwd)
	rule := config.matchFile(operation, normalized, resolved, a.cwd, resolvedCWD)
	if rule == nil || (builtin.Decision == Review && !fileRuleCanReplaceReview(builtin, rule.Action)) {
		return builtin
	}
	message := customRuleMessage(config.Output.Language, rule.ID)
	finding := Finding{
		Decision: rule.Action,
		RuleID:   rule.ID,
		Message:  message,
		Command:  string(operation),
		Target:   normalized,
	}
	return Result{Decision: rule.Action, Message: message, Findings: []Finding{finding}}
}

func analyzeFileBuiltin(operation FileOperation, normalized, resolved string, a *analyzer) Result {
	switch operation {
	case FileRead:
		if sensitiveReadBlocked(normalized, resolved, a.home) {
			a.add(Block, "sensitive-file-read", string(operation), normalized)
		} else if sensitiveReadReview(normalized, resolved, a.home) {
			a.add(Review, "sensitive-file-read-review", string(operation), normalized)
		}
	case FileEdit, FileWrite:
		if sensitiveWriteBlocked(normalized, resolved, a) {
			a.add(Block, "sensitive-file-write", string(operation), normalized)
		} else if zshProfile(normalized) {
			a.add(Review, "shell-profile-write", string(operation), normalized)
		} else if outsideWorkspace(normalized, resolved, a) {
			a.add(Review, "outside-workspace-write", string(operation), normalized)
		}
	default:
		a.add(Block, "invalid-file-operation", string(operation), normalized)
	}
	return a.result()
}

// An allow or review file rule may replace contextual workspace review, but it
// cannot weaken credential or persistence review. A block rule can always make
// the built-in result stricter.
func fileRuleCanReplaceReview(builtin Result, action Decision) bool {
	if action == Block {
		return true
	}
	for _, finding := range builtin.Findings {
		if finding.RuleID != "outside-workspace-write" {
			return false
		}
	}
	return true
}

func validToolPath(path string) bool {
	return path != "" && path != "-" && len(path) <= maxToolPathBytes && utf8.ValidString(path) &&
		!strings.ContainsFunc(path, unicode.IsControl)
}

func sensitiveReadBlocked(normalized, resolved, home string) bool {
	for _, path := range []string{normalized, resolved} {
		base := strings.ToLower(filepath.Base(path))
		if privateKeyBasename(base) || decryptionKeyBasename(base) || credentialBasename(base) {
			return true
		}
		if pathHasDirectory(path, ".gnupg", "private-keys-v1.d") ||
			pathHasDirectory(path, ".gnupg") && strings.HasPrefix(base, "secring") ||
			pathHasDirectory(path, ".ssh") && strings.HasPrefix(base, "id_") {
			return true
		}
		for _, privatePath := range privateCredentialPaths(home) {
			if pathMatchesRoot(path, privatePath) {
				return true
			}
		}
	}
	return false
}

func sensitiveReadReview(normalized, resolved, home string) bool {
	for _, path := range []string{normalized, resolved} {
		base := strings.ToLower(filepath.Base(path))
		if dotenvBasename(base) || base == "authorized_keys" || reviewCredentialBasename(base) {
			return true
		}
		for _, reviewPath := range reviewCredentialPaths(home) {
			if pathMatchesRoot(path, reviewPath) {
				return true
			}
		}
	}
	return false
}

func sensitiveWriteBlocked(normalized, resolved string, a *analyzer) bool {
	// The skill trees are carved out of the control surface, but only from it:
	// a credential or a shell profile dropped inside one is still blocked below.
	skillWrite := agentSkillWrite(normalized, resolved, a.home)
	for _, path := range []string{normalized, resolved} {
		base := strings.ToLower(filepath.Base(path))
		if dotenvBasename(base) || privateKeyBasename(base) || decryptionKeyBasename(base) ||
			credentialBasename(base) || reviewCredentialBasename(base) || bashProfile(path) {
			return true
		}
		if pathHasDirectory(path, "secrets") || pathHasDirectory(path, ".secrets") ||
			pathHasDirectory(path, ".ssh") || pathHasDirectory(path, ".gnupg") ||
			pathHasDirectory(path, ".aws") || pathHasDirectory(path, ".azure") ||
			pathHasDirectory(path, ".gcloud") || pathHasDirectory(path, ".git", "hooks") ||
			pathHasDirectory(path, "Library", "LaunchAgents") || pathHasDirectory(path, "Library", "LaunchDaemons") {
			return true
		}
		if skillWrite {
			continue
		}
		for _, root := range protectedFileWriteRoots(a) {
			if pathMatchesRoot(path, root) {
				return true
			}
		}
	}
	return false
}

func privateKeyBasename(base string) bool {
	switch base {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".jks"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func decryptionKeyBasename(base string) bool {
	return base == ".env.keys" || strings.HasSuffix(base, ".keys")
}

func credentialBasename(base string) bool {
	return base == "credentials.json" ||
		(strings.HasPrefix(base, "service-account") || strings.HasPrefix(base, "service_account")) && strings.HasSuffix(base, ".json") ||
		base == "auth.json"
}

func reviewCredentialBasename(base string) bool {
	switch base {
	case ".netrc", ".npmrc", ".pypirc", ".git-credentials":
		return true
	default:
		return false
	}
}

func dotenvBasename(base string) bool {
	if base == ".env" {
		return true
	}
	if !strings.HasPrefix(base, ".env.") {
		return false
	}
	switch base {
	case ".env.example", ".env.sample", ".env.template", ".env.dist":
		return false
	default:
		return true
	}
}

func bashProfile(path string) bool {
	switch strings.ToLower(filepath.Base(path)) {
	case ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile":
		return true
	default:
		return false
	}
}

func zshProfile(path string) bool {
	switch strings.ToLower(filepath.Base(path)) {
	case ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout":
		return true
	default:
		return false
	}
}

func privateCredentialPaths(home string) []string {
	return []string{
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".azure", "accessTokens.json"),
		filepath.Join(home, ".gcloud", "application_default_credentials.json"),
		filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"),
		filepath.Join(home, ".config", "gh", "hosts.yml"),
		filepath.Join(home, ".docker", "config.json"),
		filepath.Join(home, ".kube", "config"),
		filepath.Join(home, ".codex", "auth.json"),
		filepath.Join(home, ".pi", "agent", "auth.json"),
	}
}

func reviewCredentialPaths(home string) []string {
	return []string{
		filepath.Join(home, ".ssh", "authorized_keys"),
	}
}

func protectedFileWriteRoots(a *analyzer) []string {
	return agentControlRoots(a.home)
}

func pathMatchesRoot(path, root string) bool {
	return filePathWithin(path, filepath.Clean(root)) || filePathWithin(path, resolvePathSymlinks(root))
}

func filePathWithin(path, root string) bool {
	if runtime.GOOS == "darwin" {
		path = strings.ToLower(path)
		root = strings.ToLower(root)
	}
	return pathWithin(path, root)
}

func pathHasDirectory(path string, components ...string) bool {
	pathComponents := splitPathComponents(filepath.Clean(path))
	if len(components) > len(pathComponents) {
		return false
	}
	for start := 0; start+len(components) <= len(pathComponents); start++ {
		matched := true
		for offset, component := range components {
			left := pathComponents[start+offset]
			if !runtimePathEqual(left, component) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func splitPathComponents(path string) []string {
	volume := filepath.VolumeName(path)
	path = strings.TrimPrefix(path, volume)
	path = strings.Trim(path, `/\\`)
	if path == "" {
		return nil
	}
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
}

func runtimePathEqual(left, right string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

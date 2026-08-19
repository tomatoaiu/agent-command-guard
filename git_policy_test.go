package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestProtectedBranchExceptionAllowsOnlyExactMatrixCells(t *testing.T) {
	repository := committedRepository(t, "main")
	otherRepository := committedRepository(t, "main")
	config := Config{Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{
		{
			Repository: repository,
			Branch:     "main",
			Operations: []string{"commit", "push"},
			Remote:     "origin",
		},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	subdirectory := filepath.Join(repository, "nested")
	if err := os.Mkdir(subdirectory, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		command string
		cwd     string
	}{
		{"commit", "git commit -m test", repository},
		{"amend", "git commit --amend --no-edit", repository},
		{"repository subdirectory", "git commit -m test", subdirectory},
		{"git C", "git -C " + repository + " commit -m test", t.TempDir()},
		// "-" is the stdin placeholder for -F and "--" ends the option list;
		// neither abbreviates --no-verify.
		{"message from stdin", "git commit -F -", repository},
		{"pathspec separator", "git commit -m test -- README.md", repository},
		{"push short ref", "git push origin main", repository},
		{"push explicit ref", "git push origin main:main", repository},
		{"push full ref", "git push origin refs/heads/main:refs/heads/main", repository},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, test.cwd, config)
			if result.Decision != Allow || !hasRule(result, "protected-branch-exception") {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}

	for _, test := range []struct {
		name    string
		command string
		cwd     string
		rule    string
	}{
		{"other repository commit", "git commit -m test", otherRepository, "protected-branch-direct-commit"},
		{"other repository push", "git push origin main", otherRepository, "protected-branch-push"},
		{"wrong remote", "git push upstream main", repository, "protected-branch-push"},
		{"different source", "git push origin feature:main", repository, "protected-branch-push"},
		{"head source", "git push origin HEAD:main", repository, "protected-branch-push"},
		{"at source", "git push origin @:main", repository, "protected-branch-push"},
		{"plain forced ref", "git push origin +main", repository, "protected-branch-push"},
		{"force", "git push --force origin main", repository, "protected-branch-push"},
		{"force with lease", "git push --force-with-lease origin main", repository, "protected-branch-push"},
		{"multiple refs", "git push origin main feature", repository, "protected-branch-push"},
		{"push option", "git push -o ci.skip origin main", repository, "protected-branch-push"},
		{"repository option", "git push --repo origin main", repository, "protected-branch-push"},
		{"bare push", "git push", repository, "protected-branch-push"},
		{"bulk push", "git push --all origin", repository, "protected-branch-bulk-push"},
		{"mirror push", "git push --mirror origin", repository, "protected-branch-bulk-push"},
		{"delete flag", "git push origin --delete main", repository, "protected-remote-branch-delete"},
		{"delete refspec", "git push origin :main", repository, "protected-remote-branch-delete"},
		{"no verify", "git commit --no-verify -m test", repository, "protected-branch-direct-commit"},
		{"short no verify", "git commit -n -m test", repository, "protected-branch-direct-commit"},
		{"abbreviated no verify", "git commit --no-ver -m test", repository, "protected-branch-direct-commit"},
		{"dynamic commit argument", `git commit -m "$(printf test)"`, repository, "protected-branch-direct-commit"},
		{"compound commit and push", "git commit -m test && git push origin main", repository, "protected-branch-exception-compound-command"},
		{"compound push and status", "git push origin main && git status", repository, "protected-branch-exception-compound-command"},
		{"compound push separator", "git push origin main; true", repository, "protected-branch-exception-compound-command"},
		{"commit pipeline", `git commit -m test | tee commit.log`, repository, "protected-branch-exception-pipeline"},
		{"push pipeline", `git push origin main | tee push.log`, repository, "protected-branch-exception-pipeline"},
		{"commit redirect", `git commit -m test > commit.log`, repository, "protected-branch-exception-redirection"},
		{"push redirect", `git push origin main > push.log`, repository, "protected-branch-exception-redirection"},
		{"nested commit shell", `bash -c 'git commit -m test'`, repository, "protected-branch-exception-indirect-invocation"},
		{"nested push shell", `bash -c 'git push origin main'`, repository, "protected-branch-exception-indirect-invocation"},
		{"commit subshell", `(git commit -m test)`, repository, "protected-branch-exception-indirect-invocation"},
		{"push subshell", `(git push origin main)`, repository, "protected-branch-exception-indirect-invocation"},
		{"environment commit wrapper", `env GIT_CONFIG_NOSYSTEM=1 git commit -m test`, repository, "protected-branch-exception-indirect-invocation"},
		{"environment push wrapper", `env GIT_CONFIG_NOSYSTEM=1 git push origin main`, repository, "protected-branch-exception-indirect-invocation"},
		{"assignment wrapper", `GIT_CONFIG_NOSYSTEM=1 git commit -m test`, repository, "protected-branch-exception-indirect-invocation"},
		{"command wrapper", `command git push origin main`, repository, "protected-branch-exception-indirect-invocation"},
		{"exec wrapper", `exec git push origin main`, repository, "protected-branch-exception-indirect-invocation"},
		{"compound wrong remote", `git push upstream main && git status`, repository, "protected-branch-push"},
		{"compound force", `git push --force origin main && git status`, repository, "protected-branch-push"},
		{"git config override", `git -c core.hooksPath=/dev/null commit -m test`, repository, "protected-branch-direct-commit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, test.cwd, config)
			if result.Decision != Block || !hasRule(result, test.rule) {
				t.Fatalf("got decision=%s findings=%+v, want block rule=%s", result.Decision, result.Findings, test.rule)
			}
			if hasRule(result, "protected-branch-exception") {
				t.Fatalf("unsafe command received the exception: %+v", result.Findings)
			}
			if !strings.HasPrefix(test.rule, "protected-branch-exception-") {
				for _, finding := range result.Findings {
					if strings.HasPrefix(finding.RuleID, "protected-branch-exception-") {
						t.Fatalf("configuration or argument mismatch received a shell ineligibility rule: %+v", result.Findings)
					}
				}
			}
		})
	}

	for _, command := range []string{`git push origin "$BRANCH"`, `git push "$REMOTE" main`} {
		result := analyzePOSIXWithConfig(command, repository, config)
		if result.Decision != Review || !hasRule(result, "git-dynamic-push-ref") {
			t.Fatalf("%q: got decision=%s findings=%+v", command, result.Decision, result.Findings)
		}
		for _, finding := range result.Findings {
			if strings.HasPrefix(finding.RuleID, "protected-branch-exception-") {
				t.Fatalf("%q: dynamic value reported a matching exception: %+v", command, result.Findings)
			}
		}
	}
}

func TestEligiblePOSIXProtectedGitExceptionReasons(t *testing.T) {
	for _, test := range []struct {
		name     string
		command  string
		depth    int
		eligible bool
		reason   protectedGitExceptionIneligibility
	}{
		{"direct", "git push origin main", 0, true, protectedGitExceptionEligible},
		{"multiple statements", "git push origin main; git status", 0, false, protectedGitExceptionCompoundCommand},
		{"and chain", "git push origin main && git status", 0, false, protectedGitExceptionCompoundCommand},
		{"pipeline", "git push origin main | tee push.log", 0, false, protectedGitExceptionPipeline},
		{"redirection", "git push origin main > push.log", 0, false, protectedGitExceptionRedirection},
		{"subshell", "(git push origin main)", 0, false, protectedGitExceptionIndirect},
		{"wrapper", "env GIT_CONFIG_NOSYSTEM=1 git push origin main", 0, false, protectedGitExceptionIndirect},
		{"assignment", "GIT_CONFIG_NOSYSTEM=1 git commit -m test", 0, false, protectedGitExceptionIndirect},
		{"negation", "! git push origin main", 0, false, protectedGitExceptionIndirect},
		{"background", "git push origin main &", 0, false, protectedGitExceptionIndirect},
		{"nested", "git push origin main", 1, false, protectedGitExceptionIndirect},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(test.command), "test")
			if err != nil {
				t.Fatal(err)
			}
			got := eligiblePOSIXProtectedGitException(file, test.depth, userHomeDir())
			if got.Eligible != test.eligible || got.Reason != test.reason {
				t.Fatalf("got %+v, want eligible=%t reason=%q", got, test.eligible, test.reason)
			}
		})
	}
}

func TestProtectedGitExceptionRuleID(t *testing.T) {
	for reason, want := range map[protectedGitExceptionIneligibility]string{
		protectedGitExceptionCompoundCommand: "protected-branch-exception-compound-command",
		protectedGitExceptionPipeline:        "protected-branch-exception-pipeline",
		protectedGitExceptionRedirection:     "protected-branch-exception-redirection",
		protectedGitExceptionIndirect:        "protected-branch-exception-indirect-invocation",
		"unknown":                            "protected-branch-exception-requires-standalone",
	} {
		if got := protectedGitExceptionRuleID(reason); got != want {
			t.Errorf("reason %q: got %q, want %q", reason, got, want)
		}
	}
}

func TestProtectedBranchExceptionSeparatesOperationsAndBranches(t *testing.T) {
	mainRepository := committedRepository(t, "main")
	masterRepository := committedRepository(t, "master")

	commitOnly := Config{Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{
		{Repository: mainRepository, Branch: "main", Operations: []string{"commit"}},
	}}}
	if err := commitOnly.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if result := analyzePOSIXWithConfig("git commit -m test", mainRepository, commitOnly); result.Decision != Allow {
		t.Fatalf("commit-only commit: got %s findings=%+v", result.Decision, result.Findings)
	}
	if result := analyzePOSIXWithConfig("git push origin main", mainRepository, commitOnly); result.Decision != Block {
		t.Fatalf("commit-only push: got %s findings=%+v", result.Decision, result.Findings)
	}

	pushOnly := Config{Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{
		{Repository: mainRepository, Branch: "main", Operations: []string{"push"}, Remote: "origin"},
	}}}
	if err := pushOnly.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if result := analyzePOSIXWithConfig("git push origin main", mainRepository, pushOnly); result.Decision != Allow {
		t.Fatalf("push-only push: got %s findings=%+v", result.Decision, result.Findings)
	}
	if result := analyzePOSIXWithConfig("git commit -m test", mainRepository, pushOnly); result.Decision != Block {
		t.Fatalf("push-only commit: got %s findings=%+v", result.Decision, result.Findings)
	}
	if result := analyzePOSIXWithConfig("git commit -m test", masterRepository, pushOnly); result.Decision != Block {
		t.Fatalf("wrong branch: got %s findings=%+v", result.Decision, result.Findings)
	}
}

func TestProtectedBranchExceptionCanonicalizesRepository(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	repository := committedRepository(t, "main")
	link := filepath.Join(t.TempDir(), "repository-link")
	if err := os.Symlink(repository, link); err != nil {
		t.Fatal(err)
	}
	config := Config{Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{
		{Repository: link, Branch: "main", Operations: []string{"commit"}},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if result := analyzePOSIXWithConfig("git commit -m test", repository, config); result.Decision != Allow {
		t.Fatalf("symlink repository: got %s findings=%+v", result.Decision, result.Findings)
	}
}

func TestProtectedBranchExceptionDoesNotFollowALaterSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation depends on runner privileges")
	}
	repository := committedRepository(t, "main")
	configuredPath := filepath.Join(t.TempDir(), "not-created-yet")
	config := Config{Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{
		{Repository: configuredPath, Branch: "main", Operations: []string{"commit"}},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(repository, configuredPath); err != nil {
		t.Fatal(err)
	}
	result := analyzePOSIXWithConfig("git commit -m test", repository, config)
	if result.Decision != Block || !hasRule(result, "protected-branch-direct-commit") {
		t.Fatalf("later symlink must fail closed: got %s findings=%+v", result.Decision, result.Findings)
	}
}

func TestProtectedBranchExceptionConfigValidation(t *testing.T) {
	repository := committedRepository(t, "main")
	for _, test := range []struct {
		name      string
		exception GitProtectedBranchException
		want      string
	}{
		{"missing repository", GitProtectedBranchException{Branch: "main", Operations: []string{"commit"}}, "repository"},
		{"missing branch", GitProtectedBranchException{Repository: repository, Operations: []string{"commit"}}, "branch"},
		{"wildcard branch", GitProtectedBranchException{Repository: repository, Branch: "release/*", Operations: []string{"commit"}}, "branch"},
		{"hidden branch component", GitProtectedBranchException{Repository: repository, Branch: "release/.hidden", Operations: []string{"commit"}}, "branch"},
		{"missing operations", GitProtectedBranchException{Repository: repository, Branch: "main"}, "operations"},
		{"unknown operation", GitProtectedBranchException{Repository: repository, Branch: "main", Operations: []string{"reset"}}, "operation"},
		{"duplicate operation", GitProtectedBranchException{Repository: repository, Branch: "main", Operations: []string{"commit", "commit"}}, "duplicate"},
		{"push without remote", GitProtectedBranchException{Repository: repository, Branch: "main", Operations: []string{"push"}}, "remote"},
		{"URL remote", GitProtectedBranchException{Repository: repository, Branch: "main", Operations: []string{"push"}, Remote: "https://example.com/repo.git"}, "remote"},
		{"option-like remote", GitProtectedBranchException{Repository: repository, Branch: "main", Operations: []string{"push"}, Remote: "-origin"}, "remote"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := Config{Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{test.exception}}}
			err := config.prepare(t.TempDir())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestLoadProtectedBranchException(t *testing.T) {
	directory := t.TempDir()
	repository := committedRepository(t, "main")
	path := filepath.Join(directory, "config.toml")
	contents := []byte(`[git]
protected_branches = ["develop"]

[[git.protected_branch_exceptions]]
repository = "` + strings.ReplaceAll(repository, `\`, `\\`) + `"
branch = "main"
operations = ["commit", "push"]
remote = "origin"
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Git.ProtectedBranchExceptions) != 1 {
		t.Fatalf("exceptions: got %+v", config.Git.ProtectedBranchExceptions)
	}
	exception := config.Git.ProtectedBranchExceptions[0]
	if exception.Repository != canonicalFilesystemPath(repository) || exception.Branch != "main" || exception.Remote != "origin" {
		t.Fatalf("exception: got %+v", exception)
	}
}

func committedRepository(t *testing.T, branch string) string {
	t.Helper()
	repository := t.TempDir()
	command := exec.Command("git", "init", "-b", branch, repository)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	command = exec.Command("git", "-C", repository, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "initial")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	return repository
}

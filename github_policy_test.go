package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	blockedRepositoryName = "example/internal-tools"
	publicRepositoryName  = "example/public-tools"
)

func TestGitHubPullRequestCreateBlocks(t *testing.T) {
	clearGitHubEnvironment(t)
	blockedRepository := repositoryWithRemote(t, "main", "git@github.com:"+blockedRepositoryName+".git")
	blockedSubdirectory := filepath.Join(blockedRepository, "nested", "directory")
	if err := os.MkdirAll(blockedSubdirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	publicRepository := repositoryWithRemote(t, "main", "https://github.com/"+publicRepositoryName+".git")
	config := Config{
		Git: GitConfig{ProtectedBranchExceptions: []GitProtectedBranchException{
			{Repository: blockedRepository, Branch: "main", Operations: []string{"commit", "push"}, Remote: "origin"},
		}},
		GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
			{Repository: blockedRepositoryName},
		}},
	}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		command string
		cwd     string
	}{
		{"direct create", "gh pr create --fill", blockedRepository},
		{"new alias", "gh pr new --fill", blockedRepository},
		{"command wrapper", "command gh pr create --fill", blockedRepository},
		{"command end-options wrapper", "command -- gh pr create --fill", blockedRepository},
		{"nice wrapper", "nice -n 5 gh pr create --fill", blockedRepository},
		{"timeout wrapper", "timeout 5 gh pr create --fill", blockedRepository},
		{"setsid wrapper", "setsid -f gh pr create --fill", blockedRepository},
		{"nested shell", "bash -c 'gh pr create --fill'", blockedRepository},
		{"changed working directory", "cd " + posixLiteral(blockedRepository) + " && gh pr create --fill", publicRepository},
		{"sequential working directories", "cd " + posixLiteral(blockedRepository) + " && cd ./nested/directory && gh pr create --fill", publicRepository},
		{"env working directory", "env --chdir " + posixLiteral(blockedSubdirectory) + " gh pr create --fill", publicRepository},
		{"env split string", "env -S 'gh pr create --fill'", blockedRepository},
		{"xargs wrapper", "printf '%s\\n' ignored | xargs gh pr create --fill", blockedRepository},
		{"literal command variables", `GROUP=pr; ACTION=create; gh "$GROUP" "$ACTION" --fill`, blockedRepository},
		{"shell alias definition", "alias submit-pr='gh pr create -R " + blockedRepositoryName + " --fill'; submit-pr", publicRepository},
		{"leading repository flag", "gh --repo " + blockedRepositoryName + " pr create --fill", publicRepository},
		{"inherited repository flag", "gh pr --repo " + blockedRepositoryName + " create --fill", publicRepository},
		{"attached repository flag", "gh pr create --repo=" + blockedRepositoryName + " --fill", publicRepository},
		{"host-qualified repository", "gh pr create -R github.com/" + blockedRepositoryName + " --fill", publicRepository},
		{"host-qualified environment with dynamic default host", `GH_HOST="$HOST" GH_REPO=github.com/` + blockedRepositoryName + ` gh pr create --fill`, publicRepository},
		{"prefix repository environment", "GH_REPO=" + blockedRepositoryName + " gh pr create --fill", publicRepository},
		{"exported repository environment", "export GH_REPO=" + blockedRepositoryName + "; gh pr create --fill", publicRepository},
		{"separately exported repository environment", "GH_REPO=" + blockedRepositoryName + "; export GH_REPO; gh pr create --fill", publicRepository},
		{"all-export repository environment", "set -a; GH_REPO=" + blockedRepositoryName + "; gh pr create --fill", publicRepository},
		{"declared exported repository environment", "declare -x GH_REPO=" + blockedRepositoryName + "; gh pr create --fill", publicRepository},
		{"env repository environment", "env GH_REPO=" + blockedRepositoryName + " gh pr create --fill", publicRepository},
		{"wrapped env repository environment", "nice -n 5 env GH_REPO=" + blockedRepositoryName + " gh pr create --fill", publicRepository},
		{"stack submit", "gh stack submit", blockedRepository},
		{"agent task", "gh agent-task create 'Fix the failing test'", blockedRepository},
		{"agent task alias", "gh agent create 'Fix the failing test' -R " + blockedRepositoryName, publicRepository},
		{"agent task dry-run prompt", "gh agent-task create -- --dry-run", blockedRepository},
		{"agent task help prompt", "gh agent-task create -- --help", blockedRepository},
		{"pull request dry-run positional", "gh pr create -- --dry-run", blockedRepository},
		{"rest explicit method", "gh api -X POST repos/" + blockedRepositoryName + "/pulls --input payload.json", publicRepository},
		{"rest attached method", "gh api --method=POST /repos/" + blockedRepositoryName + "/pulls --input payload.json", publicRepository},
		{"rest inferred post", "gh api repos/" + blockedRepositoryName + "/pulls -f title=test -f head=feature -f base=main", publicRepository},
		{"rest absolute URL", "gh api https://api.github.com/repos/" + blockedRepositoryName + "/pulls -XPOST --input payload.json", publicRepository},
		{"rest URL query", "gh api 'repos/" + blockedRepositoryName + "/pulls?draft=true' -XPOST --input payload.json", publicRepository},
		{"rest encoded owner", "gh api repos/%65xample/internal-tools/pulls -f title=test", publicRepository},
		{"rest placeholders", "gh api repos/{owner}/{repo}/pulls -f title=test -f head=feature -f base=main", blockedRepository},
		{"graphql mutation", `gh api graphql -f 'query=mutation { createPullRequest(input: $input) { pullRequest { id } } }'`, publicRepository},
		{"graphql absolute URL", `gh api https://api.github.com/graphql -f 'query=mutation { createPullRequest(input: $input) { pullRequest { id } } }'`, publicRepository},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, test.cwd, config)
			if result.Decision != Block || !hasRule(result, "github-pull-request-create") {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}

	for _, test := range []struct {
		name    string
		command string
		cwd     string
	}{
		{"view pull request", "gh pr view 1", blockedRepository},
		{"core GitHub command", "gh issue list", blockedRepository},
		{"GitHub CLI version", "gh --version", blockedRepository},
		{"command lookup", "command -v gh", blockedRepository},
		{"create dry run", "gh pr create --dry-run --fill", blockedRepository},
		{"create help", "gh pr create --help", blockedRepository},
		{"explicit public repository", "gh pr create -R " + publicRepositoryName + " --fill", blockedRepository},
		{"public repository", "gh pr create --fill", publicRepository},
		{"read-only remote command before create", "git remote -v && gh pr create --fill", publicRepository},
		{"rest list pull requests", "gh api -X GET repos/" + blockedRepositoryName + "/pulls", publicRepository},
		{"rest create issue", "gh api repos/" + blockedRepositoryName + "/issues -f title=test", publicRepository},
		{"graphql query", `gh api graphql -f 'query=query { viewer { login } }'`, publicRepository},
		{"dynamic GET endpoint", `gh api -X GET "$ENDPOINT"`, blockedRepository},
		{"custom command in public repository", "gh dashboard", publicRepository},
		{"local merge", "git merge feature", blockedRepository},
		{"protected branch push exception", "git push origin main", blockedRepository},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, test.cwd, config)
			if result.Decision != Allow {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}

	result := analyzePOSIX("gh pr create --fill", blockedRepository)
	if result.Decision != Allow {
		t.Fatalf("policy must be opt-in: got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestGitHubPullRequestCreateBlockFailsClosedForUnknownOperation(t *testing.T) {
	clearGitHubEnvironment(t)
	blockedRepository := repositoryWithRemote(t, "main", "git@github.com:"+blockedRepositoryName+".git")
	publicRepository := repositoryWithRemote(t, "main", "https://github.com/"+publicRepositoryName+".git")
	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Repository: blockedRepositoryName},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		command string
		cwd     string
	}{
		{"custom alias or extension", "gh submit-pr", blockedRepository},
		{"custom alias or extension help", "gh submit-pr --help", blockedRepository},
		{"dynamic root command", `gh "$COMMAND"`, blockedRepository},
		{"dynamic pull request operation", `gh pr "$ACTION"`, blockedRepository},
		{"dynamic mutating REST endpoint", `gh api "$ENDPOINT" -f title=test`, publicRepository},
		{"GraphQL input file", "gh api graphql -X POST --input payload.json", publicRepository},
		{"GraphQL query file", "gh api graphql -F query=@mutation.graphql", publicRepository},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, test.cwd, config)
			if result.Decision != Block || !hasRule(result, "github-pull-request-operation-unknown") {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

func TestGitHubPullRequestCreateBlockFailsClosedForUnknownTarget(t *testing.T) {
	clearGitHubEnvironment(t)
	publicRepository := repositoryWithRemote(t, "main", "https://github.com/"+publicRepositoryName+".git")
	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Repository: blockedRepositoryName},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		command string
		cwd     string
	}{
		{"dynamic explicit repository", `gh pr create -R "$TARGET" --fill`, publicRepository},
		{"dynamic attached repository", `gh pr create --repo="$TARGET" --fill`, publicRepository},
		{"dynamic env repository", `env GH_REPO="$TARGET" gh pr create --fill`, publicRepository},
		{"dynamic exported repository", `export GH_REPO="$TARGET"; gh pr create --fill`, publicRepository},
		{"remote URL mutation", "git remote set-url origin git@github.com:" + blockedRepositoryName + ".git && gh pr create --fill", publicRepository},
		{"remote config mutation", "git config remote.origin.url git@github.com:" + blockedRepositoryName + ".git && gh pr create --fill", publicRepository},
		{"GitHub default repository mutation", "gh repo set-default " + blockedRepositoryName + " && gh pr create --fill", publicRepository},
		{"dynamic working directory", `cd "$TARGET" && gh pr create --fill`, publicRepository},
		{"dynamic env working directory", `env --chdir "$TARGET" gh pr create --fill`, publicRepository},
		{"dynamic host", `GH_HOST="$HOST" gh pr create -R example/internal-tools --fill`, publicRepository},
		{"unrelated dynamic env value", `env FEATURE="$VALUE" gh pr create --fill`, t.TempDir()},
		{"xargs replacement repository", `printf '%s\\n' example/internal-tools | xargs -I{} gh pr create -R {}`, publicRepository},
		{"xargs default replacement repository", `printf '%s\\n' example/internal-tools | xargs -i gh pr create -R {}`, publicRepository},
		{"missing repository context", "gh pr create --fill", t.TempDir()},
		{"placeholder without repository context", "gh api repos/{owner}/{repo}/pulls -f title=test", t.TempDir()},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, test.cwd, config)
			if result.Decision != Block || !hasRule(result, "github-pull-request-target-unknown") {
				t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
			}
		})
	}
}

func TestGitHubPullRequestCreateBlockSupportsEnterpriseHosts(t *testing.T) {
	clearGitHubEnvironment(t)
	const host = "git.example.test"
	const repositoryName = "example/internal-tools"
	repository := repositoryWithRemote(t, "main", "ssh://git@"+host+"/"+repositoryName+".git")
	publicRepository := repositoryWithRemote(t, "main", "https://github.com/"+publicRepositoryName+".git")
	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Host: host, Repository: repositoryName},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		command string
		cwd     string
	}{
		{"gh pr create --fill", repository},
		{"gh pr create -R " + host + "/" + repositoryName + " --fill", publicRepository},
		{"gh api --hostname " + host + " repos/" + repositoryName + "/pulls -f title=test", publicRepository},
		{"GH_HOST=" + host + " gh pr create -R " + repositoryName + " --fill", publicRepository},
		{"GH_HOST=" + host + " GH_REPO=" + repositoryName + " gh pr create --fill", publicRepository},
		{"env GH_HOST=" + host + " gh api repos/" + repositoryName + "/pulls -f title=test", publicRepository},
	} {
		result := analyzePOSIXWithConfig(test.command, test.cwd, config)
		if result.Decision != Block || !hasRule(result, "github-pull-request-create") {
			t.Fatalf("%q: got decision=%s findings=%+v", test.command, result.Decision, result.Findings)
		}
	}
}

func TestGitHubPullRequestCreateBlockAppliesInLinkedWorktree(t *testing.T) {
	clearGitHubEnvironment(t)
	repository := repositoryWithRemote(t, "main", "git@github.com:"+blockedRepositoryName+".git")
	worktree := filepath.Join(t.TempDir(), "feature-worktree")
	command := exec.Command("git", "-C", repository, "worktree", "add", "-b", "feature/test", worktree)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git worktree add: %v: %s", err, output)
	}
	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Repository: blockedRepositoryName},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	result := analyzePOSIXWithConfig("gh pr create --fill", worktree, config)
	if result.Decision != Block || !hasRule(result, "github-pull-request-create") {
		t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestGitHubPullRequestCreateBlockConfigValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		block GitHubPullRequestCreateBlock
		want  string
	}{
		{"missing repository", GitHubPullRequestCreateBlock{}, "repository"},
		{"repository includes host", GitHubPullRequestCreateBlock{Repository: "github.com/example/internal-tools"}, "OWNER/REPOSITORY"},
		{"repository missing owner", GitHubPullRequestCreateBlock{Repository: "internal-tools"}, "OWNER/REPOSITORY"},
		{"repository option", GitHubPullRequestCreateBlock{Repository: "-example/internal-tools"}, "repository"},
		{"URL host", GitHubPullRequestCreateBlock{Host: "https://github.com", Repository: blockedRepositoryName}, "host"},
		{"host path", GitHubPullRequestCreateBlock{Host: "github.com/api", Repository: blockedRepositoryName}, "host"},
		{"empty hostname", GitHubPullRequestCreateBlock{Host: ".", Repository: blockedRepositoryName}, "host"},
		{"empty hostname label", GitHubPullRequestCreateBlock{Host: "git..example.test", Repository: blockedRepositoryName}, "host"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{test.block}}}
			err := config.prepare(t.TempDir())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want substring %q", err, test.want)
			}
		})
	}

	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Repository: "Example/Internal-Tools"},
		{Host: "GITHUB.COM", Repository: "example/internal-tools"},
	}}}
	if err := config.prepare(t.TempDir()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate identity was accepted: %v", err)
	}
}

func TestLoadGitHubPullRequestCreateBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	contents := []byte(`[[github.pull_request_create_blocks]]
repository = "Example/Internal-Tools"

[[github.pull_request_create_blocks]]
host = "git.example.test"
repository = "example/service"
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.GitHub.PullRequestCreateBlocks) != 2 {
		t.Fatalf("blocks: got %+v", config.GitHub.PullRequestCreateBlocks)
	}
	first := config.GitHub.PullRequestCreateBlocks[0]
	if first.Host != "github.com" || first.Repository != "example/internal-tools" {
		t.Fatalf("normalized block: %+v", first)
	}
}

func TestParseGitHubRemoteRepository(t *testing.T) {
	for _, test := range []struct {
		remote string
		want   string
	}{
		{"git@github.com:example/internal-tools.git", "github.com/example/internal-tools"},
		{"ssh://git@github.com/example/internal-tools.git", "github.com/example/internal-tools"},
		{"ssh://git@ssh.github.com:443/example/internal-tools.git", "github.com/example/internal-tools"},
		{"https://github.com/example/internal-tools.git", "github.com/example/internal-tools"},
		{"ssh://git@git.example.test/example/internal-tools.git", "git.example.test/example/internal-tools"},
		{"ssh://git@git.example.test:443/example/internal-tools.git", "git.example.test/example/internal-tools"},
	} {
		t.Run(test.remote, func(t *testing.T) {
			identity, ok := parseGitHubRemoteRepository(test.remote)
			if !ok || identity.String() != test.want {
				t.Fatalf("got identity=%+v ok=%t, want %q", identity, ok, test.want)
			}
		})
	}
	for _, remote := range []string{"/tmp/repository", "file:///tmp/repository", "not-a-remote"} {
		if identity, ok := parseGitHubRemoteRepository(remote); ok {
			t.Errorf("local remote %q parsed as %+v", remote, identity)
		}
	}
}

func TestPowerShellGitHubPullRequestCreateBlock(t *testing.T) {
	clearGitHubEnvironment(t)
	if _, err := findPowerShell(); err != nil {
		if runtime.GOOS == "windows" {
			t.Fatal(err)
		}
		t.Skip("PowerShell is not installed")
	}
	blockedRepository := repositoryWithRemote(t, "main", "git@github.com:"+blockedRepositoryName+".git")
	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Repository: blockedRepositoryName},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"gh pr create -R " + blockedRepositoryName + " --fill",
		"$env:GH_REPO = '" + blockedRepositoryName + "'; gh pr create --fill",
		"Set-Location -LiteralPath '" + strings.ReplaceAll(blockedRepository, "'", "''") + "'; gh pr create --fill",
		"cd '" + strings.ReplaceAll(blockedRepository, "'", "''") + "'; gh agent-task create 'Fix the test'",
		"Set-Alias -Name submitPr -Value gh; submitPr pr create -R " + blockedRepositoryName + " --fill",
	} {
		result := AnalyzeWithConfigAndShell(command, t.TempDir(), config, ShellPowerShell)
		if result.Decision != Block || !hasRule(result, "github-pull-request-create") {
			t.Fatalf("%q: got decision=%s findings=%+v", command, result.Decision, result.Findings)
		}
	}
	command := "$env:GH_REPO = '" + blockedRepositoryName + "'; gh pr create --fill; $env:GH_REPO = '" + publicRepositoryName + "'"
	result := AnalyzeWithConfigAndShell(command, t.TempDir(), config, ShellPowerShell)
	if result.Decision != Block || !hasRule(result, "github-pull-request-target-unknown") {
		t.Fatalf("ambiguous assignment: got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestInheritedGitHubRepositoryEnvironment(t *testing.T) {
	clearGitHubEnvironment(t)
	publicRepository := repositoryWithRemote(t, "main", "https://github.com/"+publicRepositoryName+".git")
	config := Config{GitHub: GitHubConfig{PullRequestCreateBlocks: []GitHubPullRequestCreateBlock{
		{Repository: blockedRepositoryName},
	}}}
	if err := config.prepare(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_REPO", blockedRepositoryName)
	result := analyzePOSIXWithConfig("gh pr create --fill", publicRepository, config)
	if result.Decision != Block || !hasRule(result, "github-pull-request-create") {
		t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
	}
	for _, command := range []string{
		"unset GH_REPO; gh pr create --fill",
		"export -n GH_REPO; gh pr create --fill",
	} {
		result = analyzePOSIXWithConfig(command, publicRepository, config)
		if result.Decision != Allow {
			t.Fatalf("%q: got decision=%s findings=%+v", command, result.Decision, result.Findings)
		}
	}
}

func clearGitHubEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"GH_REPO", "GH_HOST"} {
		value, present := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

func posixLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func repositoryWithRemote(t *testing.T, branch, remote string) string {
	t.Helper()
	repository := committedRepository(t, branch)
	command := exec.Command("git", "-C", repository, "remote", "add", "origin", remote)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v: %s", err, output)
	}
	return repository
}

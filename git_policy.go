package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

const (
	gitOperationCommit = "commit"
	gitOperationPush   = "push"
)

type protectedGitExceptionEligibility struct {
	Eligible bool
	Reason   protectedGitExceptionIneligibility
}

type protectedGitExceptionIneligibility string

const (
	protectedGitExceptionEligible protectedGitExceptionIneligibility = ""

	protectedGitExceptionCompoundCommand protectedGitExceptionIneligibility = "compound-command"
	protectedGitExceptionPipeline        protectedGitExceptionIneligibility = "pipeline"
	protectedGitExceptionRedirection     protectedGitExceptionIneligibility = "redirection"
	protectedGitExceptionIndirect        protectedGitExceptionIneligibility = "indirect-invocation"
)

// GitProtectedBranchException is a narrow, structured exception to the
// built-in protected-branch policy. Each entry identifies one repository and
// branch exactly. Push exceptions additionally identify one remote alias.
type GitProtectedBranchException struct {
	Repository string   `toml:"repository"`
	Branch     string   `toml:"branch"`
	Operations []string `toml:"operations"`
	Remote     string   `toml:"remote"`

	operationSet map[string]bool
}

func prepareGitProtectedBranchExceptions(exceptions []GitProtectedBranchException, baseDir string) error {
	for i := range exceptions {
		exception := &exceptions[i]
		label := fmt.Sprintf("git.protected_branch_exceptions[%d]", i)

		repository, err := expandConfigPath(exception.Repository, baseDir)
		if err != nil {
			return fmt.Errorf("%s.repository: %w", label, err)
		}
		exception.Repository = canonicalFilesystemPath(repository)

		if !validExactGitBranch(exception.Branch) {
			return fmt.Errorf("%s.branch must be one exact valid branch name, got %q", label, exception.Branch)
		}
		if len(exception.Operations) == 0 {
			return fmt.Errorf("%s.operations must contain commit, push, or both", label)
		}
		exception.operationSet = make(map[string]bool, len(exception.Operations))
		for _, operation := range exception.Operations {
			if operation != gitOperationCommit && operation != gitOperationPush {
				return fmt.Errorf("%s has invalid operation %q", label, operation)
			}
			if exception.operationSet[operation] {
				return fmt.Errorf("%s has duplicate operation %q", label, operation)
			}
			exception.operationSet[operation] = true
		}
		if exception.operationSet[gitOperationPush] && !validGitRemoteAlias(exception.Remote) {
			return fmt.Errorf("%s.remote must be an explicit Git remote alias for push", label)
		}
		if exception.Remote != "" && !validGitRemoteAlias(exception.Remote) {
			return fmt.Errorf("%s.remote must contain only letters, numbers, dot, underscore, or hyphen", label)
		}
	}
	return nil
}

func (e GitProtectedBranchException) allows(operation string) bool {
	if e.operationSet != nil {
		return e.operationSet[operation]
	}
	for _, configured := range e.Operations {
		if configured == operation {
			return true
		}
	}
	return false
}

func validExactGitBranch(branch string) bool {
	if branch == "" || branch == "@" || strings.TrimSpace(branch) != branch || strings.HasPrefix(branch, "-") {
		return false
	}
	if strings.HasPrefix(branch, "/") || strings.HasSuffix(branch, "/") || strings.HasSuffix(branch, ".") || strings.HasSuffix(branch, ".lock") {
		return false
	}
	if strings.Contains(branch, "..") || strings.Contains(branch, "@{") || strings.Contains(branch, "//") {
		return false
	}
	for _, component := range strings.Split(branch, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	for _, character := range branch {
		if unicode.IsControl(character) || unicode.IsSpace(character) || strings.ContainsRune(`~^:?*[\`, character) {
			return false
		}
	}
	return true
}

func validGitRemoteAlias(remote string) bool {
	if remote == "" || !asciiAlphaNumeric(rune(remote[0])) {
		return false
	}
	for _, character := range remote {
		if asciiAlphaNumeric(character) || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func canonicalFilesystemPath(path string) string {
	path = filepath.Clean(path)
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Clean(path)
}

func sameFilesystemPath(left, right string) bool {
	left = filepath.Clean(left)
	if absolute, err := filepath.Abs(left); err == nil {
		left = absolute
	}
	right = canonicalFilesystemPath(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func gitRepositoryRoot(cwd string) string {
	output, err := gitCommand(cwd, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	root := strings.TrimSpace(string(output))
	if root == "" {
		return ""
	}
	return canonicalFilesystemPath(root)
}

func (a *analyzer) matchesProtectedBranchException(operation, gitCWD, branch, remote string) bool {
	repository := gitRepositoryRoot(gitCWD)
	if repository == "" {
		return false
	}
	for _, exception := range a.protectedBranchExceptions {
		if !exception.allows(operation) || exception.Branch != branch || !sameFilesystemPath(exception.Repository, repository) {
			continue
		}
		if operation == gitOperationPush && exception.Remote != remote {
			continue
		}
		return true
	}
	return false
}

func protectedGitExceptionRuleID(reason protectedGitExceptionIneligibility) string {
	switch reason {
	case protectedGitExceptionCompoundCommand:
		return "protected-branch-exception-compound-command"
	case protectedGitExceptionPipeline:
		return "protected-branch-exception-pipeline"
	case protectedGitExceptionRedirection:
		return "protected-branch-exception-redirection"
	case protectedGitExceptionIndirect:
		return "protected-branch-exception-indirect-invocation"
	default:
		return "protected-branch-exception-requires-standalone"
	}
}

func safeProtectedCommitArguments(args []string, known []bool) bool {
	if !allKnown(known) {
		return false
	}
	for _, arg := range args {
		option := strings.SplitN(arg, "=", 2)[0]
		// Git accepts unambiguous abbreviations, so "--no-ver" disables the
		// hooks just as "--no-verify" does. The prefix test therefore has to
		// run in this direction, but it only describes a long option: a bare
		// "-" is the stdin placeholder in "commit -F -", and "--" ends the
		// option list. Neither abbreviates --no-verify, so requiring a leading
		// "--" plus at least one more character keeps them out.
		if strings.HasPrefix(option, "--") && len(option) > 2 && strings.HasPrefix("--no-verify", option) {
			return false
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "n") {
			return false
		}
	}
	return true
}

func safeGitGlobalsForException(args []string, known []bool) bool {
	for len(args) > 0 {
		if len(known) == 0 || !known[0] {
			return false
		}
		if args[0] == "-C" {
			if len(args) < 2 || len(known) < 2 || !known[1] {
				return false
			}
			args, known = args[2:], known[2:]
			continue
		}
		if strings.HasPrefix(args[0], "-C") && len(args[0]) > 2 {
			args, known = args[1:], known[1:]
			continue
		}
		return !strings.HasPrefix(args[0], "-")
	}
	return false
}

func exactProtectedPush(parsed gitPushArgs, branch string) bool {
	if parsed.hasOptions || parsed.repositoryOption || len(parsed.refspecs) != 1 {
		return false
	}
	source, target, ok := exactPushBranches(parsed.refspecs[0])
	return ok && source == branch && target == branch
}

func exactPushBranches(refspec string) (string, string, bool) {
	if refspec == "" || strings.HasPrefix(refspec, "+") || strings.Count(refspec, ":") > 1 {
		return "", "", false
	}
	source := refspec
	target := refspec
	if before, after, found := strings.Cut(refspec, ":"); found {
		source, target = before, after
	}
	source, sourceOK := exactLocalBranch(source)
	target, targetOK := exactLocalBranch(target)
	return source, target, sourceOK && targetOK
}

func exactLocalBranch(ref string) (string, bool) {
	if strings.HasPrefix(ref, "refs/heads/") {
		ref = strings.TrimPrefix(ref, "refs/heads/")
	} else if strings.HasPrefix(ref, "refs/") {
		return "", false
	}
	if !validExactGitBranch(ref) {
		return "", false
	}
	return ref, true
}

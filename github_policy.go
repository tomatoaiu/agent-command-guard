package main

import "strings"

func (a *analyzer) inspectGitHub(args []string, known []bool) {
	if len(a.githubPullRequestCreateBlocks) == 0 {
		return
	}
	if len(args) == 1 && ghInvocationIsReadOnly(args, known) {
		return
	}
	command, index, commandKnown := ghRootCommand(args, known)
	if !commandKnown {
		a.blockUnknownGitHubPullRequestOperation(args, known)
		return
	}
	if ghInvocationIsReadOnly(args, known) && (knownGitHubRootCommand(command) || knownPullRequestCreatingGitHubRoot(command)) {
		return
	}
	switch command {
	case "pr":
		verb, _, verbKnown := ghSubcommand(args, known, index+1)
		if !verbKnown {
			a.blockUnknownGitHubPullRequestOperation(args, known)
			return
		}
		if (verb == "create" || verb == "new") && !ghInvocationIsDryRun(args, known) {
			a.blockGitHubPullRequestTarget(args, known)
		}
	case "agent-task", "agent-tasks", "agent", "agents":
		verb, _, verbKnown := ghSubcommand(args, known, index+1)
		if !verbKnown {
			a.blockUnknownGitHubPullRequestOperation(args, known)
			return
		}
		if verb == "create" {
			a.blockGitHubPullRequestTarget(args, known)
		}
	case "stack":
		verb, _, verbKnown := ghSubcommand(args, known, index+1)
		if !verbKnown {
			a.blockUnknownGitHubPullRequestOperation(args, known)
			return
		}
		if verb == "submit" && !ghInvocationIsDryRun(args, known) {
			a.blockGitHubPullRequestTarget(args, known)
		}
	case "api":
		a.inspectGitHubAPI(args[index+1:], known[index+1:])
	default:
		if !knownGitHubRootCommand(command) {
			a.blockUnknownGitHubPullRequestOperation(args, known)
		}
	}
}

func ghRootCommand(args []string, known []bool) (string, int, bool) {
	return ghSubcommand(args, known, 0)
}

func ghSubcommand(args []string, known []bool, start int) (string, int, bool) {
	endOptions := false
	for i := start; i < len(args); i++ {
		if i >= len(known) || !known[i] {
			return "", i, false
		}
		arg := args[i]
		if !endOptions && arg == "--" {
			endOptions = true
			continue
		}
		if !endOptions && ghRepositoryFlagTakesValue(arg) {
			i++
			if i >= len(args) || i >= len(known) || !known[i] {
				return "", i, false
			}
			continue
		}
		if !endOptions && (strings.HasPrefix(arg, "--repo=") || strings.HasPrefix(arg, "-R") && len(arg) > 2) {
			continue
		}
		if !endOptions && strings.HasPrefix(arg, "-") {
			continue
		}
		return strings.ToLower(arg), i, true
	}
	return "", len(args), false
}

func ghRepositoryFlagTakesValue(arg string) bool {
	return arg == "-R" || arg == "--repo"
}

func ghInvocationIsReadOnly(args []string, known []bool) bool {
	for i, arg := range args {
		if i >= len(known) || !known[i] {
			continue
		}
		if arg == "--" {
			return false
		}
		if i == len(args)-1 && (arg == "--help" || arg == "-h" || arg == "--version") {
			return true
		}
	}
	return false
}

func ghInvocationIsDryRun(args []string, known []bool) bool {
	for i, arg := range args {
		if i >= len(known) || !known[i] {
			continue
		}
		if arg == "--" {
			return false
		}
		if arg == "--dry-run" {
			return true
		}
	}
	return false
}

func knownPullRequestCreatingGitHubRoot(command string) bool {
	switch command {
	case "agent-task", "agent-tasks", "agent", "agents", "stack":
		return true
	default:
		return false
	}
}

func knownGitHubRootCommand(command string) bool {
	switch command {
	case "alias", "api", "attestation", "auth", "browse", "cache", "codespace", "completion", "config",
		"discussion", "gist", "gpg-key", "help", "issue", "label", "licenses", "org", "pr", "project",
		"release", "repo", "ruleset", "run", "search", "secret", "skill", "ssh-key", "status", "variable",
		"version", "workflow":
		return true
	default:
		return false
	}
}

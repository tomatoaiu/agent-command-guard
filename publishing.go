package main

// Publishing pushes code to a registry that other people install from, so it
// leaves the machine in a way that cannot be taken back. npm and pnpm were
// already covered; the rest of the ecosystem was not.
func publishesPackage(command string, args []string) bool {
	subcommand := firstSubcommand(args)
	switch command {
	case "npm", "pnpm", "yarn", "bun", "cargo", "poetry":
		return subcommand == "publish"
	case "gem":
		return subcommand == "push"
	case "twine":
		return subcommand == "upload"
	case "mvn":
		return containsAny(args, "deploy")
	case "gradle", "gradlew":
		return containsAny(args, "publish")
	case "dotnet":
		return adjacentSubcommand(args, "nuget", "push")
	}
	return false
}

// Pushing an image or a chart uploads a build artifact to a registry. It is
// routine enough during development to stop at review rather than a block.
func publishesContainerArtifact(command string, args []string) bool {
	switch command {
	case "docker", "podman", "helm", "nerdctl":
		return firstSubcommand(args) == "push"
	}
	return false
}

// gh subcommands that destroy a repository, a release, or the configuration
// that CI depends on. Each is a noun followed by its verb, so they are matched
// as an adjacent pair; that way a global flag before or after the pair does
// not shift the positions and hide the match.
func ghDestroys(args []string) bool {
	for _, verb := range []string{"delete", "archive", "rename"} {
		if adjacentSubcommand(args, "repo", verb) {
			return true
		}
	}
	if adjacentSubcommand(args, "repo", "edit") &&
		(containsAny(args, "--visibility") || anyArgPrefix(args, "--visibility=")) {
		return true
	}
	if adjacentSubcommand(args, "release", "delete") {
		return true
	}
	if adjacentSubcommand(args, "secret", "delete") || adjacentSubcommand(args, "variable", "delete") {
		return true
	}
	return adjacentSubcommand(args, "workflow", "disable")
}

func adjacentSubcommand(args []string, first, second string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == first && args[i+1] == second {
			return true
		}
	}
	return false
}

package main

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// posixGitHubEnvironmentOverride recovers a GitHub CLI environment variable
// when the command fixes it as a prefix assignment or an env argument. The
// value remains active while a literal nested shell is inspected because the
// child process inherits it.
func posixGitHubEnvironmentOverride(
	variable string,
	assignments []*syntax.Assign,
	argv []string,
	known []bool,
	home string,
	resolvedAssignments map[string]string,
) (wordValue, bool) {
	var override wordValue
	found := false
	for _, assignment := range assignments {
		if assignment == nil || assignment.Name == nil || assignment.Name.Value != variable {
			continue
		}
		found = true
		if assignment.Value == nil {
			override = wordValue{Known: false}
			continue
		}
		override = evalWord(assignment.Value, home, resolvedAssignments)
	}

	i := wrappedEnvCommandIndex(argv, known)
	if i < 0 {
		return override, found
	}
	for i++; i < len(argv); {
		argKnown := i < len(known) && known[i]
		arg := argv[i]
		if !argKnown {
			if strings.HasPrefix(arg, variable+"=") {
				override = wordValue{Known: false}
				found = true
				i++
				continue
			}
			if strings.Contains(arg, "=") {
				i++
				continue
			}
			return override, found
		}
		if arg == "--" {
			return override, found
		}
		if envOptionTakesValue(arg) {
			i += 2
			continue
		}
		if strings.HasPrefix(arg, "-") {
			i++
			continue
		}
		if name, value, ok := strings.Cut(arg, "="); ok {
			if name == variable {
				override = wordValue{Value: value, Known: true}
				found = true
			}
			i++
			continue
		}
		return override, found
	}
	return override, found
}

func cloneGitHubShellVariables(source map[string]wordValue) map[string]wordValue {
	cloned := make(map[string]wordValue, len(source))
	for name, value := range source {
		cloned[name] = value
	}
	return cloned
}

func cloneGitHubExportedVariables(source map[string]bool) map[string]bool {
	cloned := make(map[string]bool, len(source))
	for name, value := range source {
		cloned[name] = value
	}
	return cloned
}

func (a *analyzer) seedInheritedGitHubShellEnvironment() {
	for name, override := range map[string]*wordValue{
		"GH_REPO": a.githubRepositoryOverride,
		"GH_HOST": a.githubHostOverride,
	} {
		if override == nil {
			continue
		}
		a.githubShellVariables[name] = *override
		a.githubExportedVariables[name] = true
	}
}

func (a *analyzer) observeGitHubShellAssignment(assignment *syntax.Assign) {
	if assignment == nil || assignment.Name == nil || assignment.Value == nil {
		return
	}
	name := assignment.Name.Value
	if name != "GH_REPO" && name != "GH_HOST" {
		return
	}
	value := evalWord(assignment.Value, a.home, a.assignments)
	if assignment.Append || assignment.Index != nil || assignment.Array != nil {
		value = wordValue{Known: false}
	}
	a.githubShellVariables[name] = value
	if a.githubAllExport {
		a.githubExportedVariables[name] = true
	}
	if !a.githubExportedVariables[name] {
		return
	}
	if name == "GH_REPO" {
		a.githubRepositoryOverride = &value
	} else {
		a.githubHostOverride = &value
	}
}

func (a *analyzer) observeExportedGitHubEnvironment(assignment *syntax.Assign) {
	if assignment == nil || assignment.Name == nil {
		return
	}
	name := assignment.Name.Value
	if name != "GH_REPO" && name != "GH_HOST" {
		return
	}
	value, ok := a.githubShellVariables[name]
	if !ok {
		value = wordValue{Known: false}
		a.githubShellVariables[name] = value
	}
	a.githubExportedVariables[name] = true
	if name == "GH_REPO" {
		a.githubRepositoryOverride = &value
	} else {
		a.githubHostOverride = &value
	}
}

func (a *analyzer) observeUnexportedGitHubEnvironment(assignment *syntax.Assign) {
	if assignment == nil || assignment.Name == nil {
		return
	}
	name := assignment.Name.Value
	if name != "GH_REPO" && name != "GH_HOST" {
		return
	}
	a.githubExportedVariables[name] = false
	if name == "GH_REPO" {
		a.githubRepositoryOverride = nil
	} else {
		a.githubHostOverride = nil
	}
}

func (a *analyzer) observeGitHubRepositoryContext(command string, args []string, known []bool) {
	if len(a.githubPullRequestCreateBlocks) == 0 {
		return
	}
	switch command {
	case "set":
		if !allKnown(known) {
			return
		}
		for i, arg := range args {
			switch arg {
			case "-a":
				a.githubAllExport = true
			case "+a":
				a.githubAllExport = false
			case "-o":
				if i+1 < len(args) && args[i+1] == "allexport" {
					a.githubAllExport = true
				}
			case "+o":
				if i+1 < len(args) && args[i+1] == "allexport" {
					a.githubAllExport = false
				}
			}
		}
	case "unset":
		for i, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if i >= len(known) || !known[i] {
				a.githubRepositoryOverride = &wordValue{Known: false}
				a.githubHostOverride = &wordValue{Known: false}
				continue
			}
			switch arg {
			case "GH_REPO":
				a.githubRepositoryOverride = nil
				delete(a.githubShellVariables, arg)
				delete(a.githubExportedVariables, arg)
			case "GH_HOST":
				a.githubHostOverride = nil
				delete(a.githubShellVariables, arg)
				delete(a.githubExportedVariables, arg)
			}
		}
	case "git":
		stripped, strippedKnown, _, cwdKnown := stripGitGlobals(args, known, a.cwd)
		if !cwdKnown || len(stripped) == 0 || len(strippedKnown) == 0 || !strippedKnown[0] {
			a.githubRepositoryContextUnknown = true
			return
		}
		switch stripped[0] {
		case "init", "clone":
			a.githubRepositoryContextUnknown = true
		case "remote":
			if len(stripped) < 2 || len(strippedKnown) < 2 || !strippedKnown[1] {
				return
			}
			switch stripped[1] {
			case "add", "remove", "rm", "rename", "set-url":
				a.githubRepositoryContextUnknown = true
			}
		case "config":
			if gitConfigMayChangeGitHubTarget(stripped[1:], strippedKnown[1:]) {
				a.githubRepositoryContextUnknown = true
			}
		}
	case "gh":
		if ghInvocationIsReadOnly(args, known) {
			return
		}
		root, rootIndex, rootKnown := ghRootCommand(args, known)
		if !rootKnown || root != "repo" {
			return
		}
		subcommand, _, subcommandKnown := ghSubcommand(args, known, rootIndex+1)
		if subcommandKnown && subcommand == "set-default" && !containsAny(args, "--view", "-v") {
			a.githubRepositoryContextUnknown = true
		}
	}
}

func gitConfigMayChangeGitHubTarget(args []string, known []bool) bool {
	if len(args) != len(known) || !allKnown(known) {
		return true
	}
	mutatingFlag := false
	for _, arg := range args {
		switch arg {
		case "--add", "--replace-all", "--unset", "--unset-all", "--rename-section", "--remove-section":
			mutatingFlag = true
		}
	}
	for i, arg := range args {
		key := strings.ToLower(arg)
		targetKey := key == "remote.pushdefault" ||
			strings.HasPrefix(key, "remote.") && (strings.HasSuffix(key, ".url") || strings.HasSuffix(key, ".gh-resolved")) ||
			strings.HasPrefix(key, "branch.") && strings.HasSuffix(key, ".remote")
		if !targetKey {
			continue
		}
		if mutatingFlag {
			return true
		}
		for _, value := range args[i+1:] {
			if !strings.HasPrefix(value, "-") {
				return true
			}
		}
	}
	return false
}

const maxGitHubWorkingDirectoryCandidates = 32

func (a *analyzer) observePOSIXGitHubEnvironmentCWD(argv []string, known []bool) {
	i := wrappedEnvCommandIndex(argv, known)
	if i < 0 {
		return
	}
	for i++; i < len(argv); i++ {
		argKnown := i < len(known) && known[i]
		arg := argv[i]
		if !argKnown {
			if strings.Contains(arg, "=") {
				continue
			}
			a.githubCWDUnknown = true
			return
		}
		switch {
		case arg == "--":
			return
		case arg == "-C" || arg == "--chdir":
			i++
			if i >= len(argv) || i >= len(known) {
				a.githubCWDUnknown = true
				return
			}
			a.addGitHubWorkingDirectoryCandidate(wordValue{Value: argv[i], Known: known[i]})
		case strings.HasPrefix(arg, "--chdir="):
			a.addGitHubWorkingDirectoryCandidate(wordValue{Value: strings.TrimPrefix(arg, "--chdir="), Known: true})
		case strings.HasPrefix(arg, "-C") && len(arg) > 2:
			a.addGitHubWorkingDirectoryCandidate(wordValue{Value: arg[2:], Known: true})
		case envOptionTakesValue(arg):
			i++
		case strings.HasPrefix(arg, "-") || strings.Contains(arg, "="):
			continue
		default:
			return
		}
	}
}

func (a *analyzer) observePOSIXGitHubWorkingDirectory(argv []string, known []bool) {
	if len(argv) == 0 || len(known) == 0 || !known[0] {
		return
	}
	command := normalizeCommandName(argv[0])
	if command == "builtin" && len(argv) > 1 && len(known) > 1 && known[1] {
		argv, known = argv[1:], known[1:]
		command = normalizeCommandName(argv[0])
	}
	if command == "popd" {
		a.githubCWDUnknown = true
		return
	}
	if command != "cd" && command != "chdir" && command != "pushd" {
		return
	}
	for i := 1; i < len(argv); i++ {
		if i >= len(known) || !known[i] {
			a.githubCWDUnknown = true
			return
		}
		arg := argv[i]
		if arg == "--" {
			continue
		}
		if command == "cd" && (arg == "-L" || arg == "-P" || arg == "-e" || arg == "-@") {
			continue
		}
		if command == "pushd" && (strings.HasPrefix(arg, "+") || strings.HasPrefix(arg, "-")) {
			a.githubCWDUnknown = true
			return
		}
		if !filepath.IsAbs(arg) && arg != "." && arg != ".." &&
			!strings.HasPrefix(arg, "./") && !strings.HasPrefix(arg, "../") {
			// A non-dot relative cd can be redirected by CDPATH, which may be
			// inherited from outside the analyzed source.
			a.githubCWDUnknown = true
		}
		a.addGitHubWorkingDirectoryCandidate(wordValue{Value: arg, Known: true})
		return
	}
	if command == "cd" || command == "chdir" {
		a.addGitHubWorkingDirectoryCandidate(wordValue{Value: a.home, Known: a.home != ""})
	} else {
		a.githubCWDUnknown = true
	}
}

func (a *analyzer) observePowerShellGitHubAlias(name string, command powerShellCommand) {
	if name == "remove-alias" {
		alias, ok := powerShellNamedValue(command, "name")
		if !ok {
			values := powerShellPositionalValues(command, map[string]bool{"force": true})
			if len(values) > 0 {
				alias, ok = values[0], true
			}
		}
		if ok && alias.Known {
			delete(a.powerShellGitHubAliases, strings.ToLower(alias.Value))
		}
		return
	}
	if name != "set-alias" && name != "new-alias" {
		return
	}
	alias, aliasOK := powerShellNamedValue(command, "name")
	target, targetOK := powerShellNamedValue(command, "value")
	if !aliasOK || !targetOK {
		values := powerShellPositionalValues(command, map[string]bool{"force": true, "passthru": true})
		if !aliasOK && len(values) > 0 {
			alias, aliasOK = values[0], true
		}
		if !targetOK && len(values) > 1 {
			target, targetOK = values[1], true
		}
	}
	if !aliasOK || !alias.Known || !targetOK {
		return
	}
	aliasName := strings.ToLower(alias.Value)
	if !target.Known || normalizeCommandName(target.Value) == "gh" {
		a.powerShellGitHubAliases[aliasName] = true
	} else {
		delete(a.powerShellGitHubAliases, aliasName)
	}
}

func (a *analyzer) observePowerShellGitHubWorkingDirectory(name string, command powerShellCommand) {
	if name == "pop-location" {
		a.githubCWDUnknown = true
		return
	}
	if name != "set-location" && name != "push-location" {
		return
	}
	for _, parameter := range []string{"literalpath", "path"} {
		if value, ok := powerShellNamedValue(command, parameter); ok {
			a.addGitHubWorkingDirectoryCandidate(value)
			return
		}
	}
	values := powerShellPositionalValues(command, map[string]bool{"passthru": true})
	if len(values) > 0 {
		a.addGitHubWorkingDirectoryCandidate(values[0])
		return
	}
	if name == "set-location" {
		a.addGitHubWorkingDirectoryCandidate(wordValue{Value: a.home, Known: a.home != ""})
	} else {
		a.githubCWDUnknown = true
	}
}

func (a *analyzer) addGitHubWorkingDirectoryCandidate(directory wordValue) {
	if !directory.Known || directory.Value == "" || directory.Value == "-" || strings.HasPrefix(directory.Value, "~") {
		a.githubCWDUnknown = true
		return
	}
	bases := a.githubWorkingDirectories()
	candidates := make([]string, 0, len(bases))
	if filepath.IsAbs(directory.Value) {
		candidates = append(candidates, filepath.Clean(directory.Value))
	} else {
		for _, base := range bases {
			candidates = append(candidates, filepath.Clean(filepath.Join(base, directory.Value)))
		}
	}
	seen := make(map[string]bool, len(bases)+len(candidates))
	for _, existing := range bases {
		seen[filepath.Clean(existing)] = true
	}
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		if len(a.githubPossibleCWDs) >= maxGitHubWorkingDirectoryCandidates {
			a.githubCWDUnknown = true
			return
		}
		seen[candidate] = true
		a.githubPossibleCWDs = append(a.githubPossibleCWDs, candidate)
	}
}

func (a *analyzer) githubWorkingDirectories() []string {
	directories := make([]string, 0, len(a.githubPossibleCWDs)+1)
	seen := make(map[string]bool, len(a.githubPossibleCWDs)+1)
	for _, directory := range append([]string{a.cwd}, a.githubPossibleCWDs...) {
		directory = filepath.Clean(directory)
		if directory == "" || seen[directory] {
			continue
		}
		seen[directory] = true
		directories = append(directories, directory)
	}
	return directories
}

type githubRepositoryResolution struct {
	identities []githubRepositoryIdentity
	known      bool
}

func (a *analyzer) blockGitHubPullRequestTarget(args []string, known []bool) {
	resolution := a.resolveGitHubRepositoryTarget(args, known)
	if !resolution.known || len(resolution.identities) == 0 {
		a.add(Block, "github-pull-request-target-unknown", "gh", "dynamic")
		return
	}
	for _, identity := range resolution.identities {
		if a.blocksGitHubPullRequestCreation(identity) {
			a.add(Block, "github-pull-request-create", "gh", identity.String())
			return
		}
	}
}

func (a *analyzer) blockUnknownGitHubPullRequestOperation(args []string, known []bool) {
	resolution := a.resolveGitHubRepositoryTarget(args, known)
	if !resolution.known || len(resolution.identities) == 0 {
		a.add(Block, "github-pull-request-target-unknown", "gh", "dynamic")
		return
	}
	for _, identity := range resolution.identities {
		if a.blocksGitHubPullRequestCreation(identity) {
			a.add(Block, "github-pull-request-operation-unknown", "gh", identity.String())
			return
		}
	}
}

func (a *analyzer) resolveGitHubRepositoryTarget(args []string, known []bool) githubRepositoryResolution {
	defaultHost, hostKnown := a.defaultGitHubHost()
	if identity, present, known := explicitGitHubRepository(args, known, defaultHost, hostKnown); present {
		if !known {
			return githubRepositoryResolution{}
		}
		return githubRepositoryResolution{identities: []githubRepositoryIdentity{identity}, known: true}
	}
	if a.githubRepositoryOverride != nil {
		if !a.githubRepositoryOverride.Known {
			return githubRepositoryResolution{}
		}
		if !hostKnown && strings.Count(a.githubRepositoryOverride.Value, "/") == 1 {
			return githubRepositoryResolution{}
		}
		identity, ok := parseGitHubRepositorySelector(a.githubRepositoryOverride.Value, defaultHost)
		if !ok {
			return githubRepositoryResolution{}
		}
		return githubRepositoryResolution{identities: []githubRepositoryIdentity{identity}, known: true}
	}
	identities := make([]githubRepositoryIdentity, 0)
	seen := make(map[string]bool)
	for _, cwd := range a.githubWorkingDirectories() {
		for _, identity := range gitHubRemoteRepositories(cwd) {
			if seen[identity.key()] {
				continue
			}
			seen[identity.key()] = true
			identities = append(identities, identity)
		}
	}
	return githubRepositoryResolution{
		identities: identities,
		known:      !a.githubCWDUnknown && !a.githubRepositoryContextUnknown && len(identities) > 0,
	}
}

func (a *analyzer) defaultGitHubHost() (string, bool) {
	if a.githubHostOverride == nil {
		return defaultGitHubHost, true
	}
	if !a.githubHostOverride.Known {
		return "", false
	}
	host, err := normalizeGitHubHost(a.githubHostOverride.Value)
	return host, err == nil
}

func explicitGitHubRepository(args []string, known []bool, defaultHost string, defaultHostKnown bool) (githubRepositoryIdentity, bool, bool) {
	var selected githubRepositoryIdentity
	present := false
	for i := 0; i < len(args); i++ {
		argKnown := i < len(known) && known[i]
		arg := args[i]
		value := ""
		valueKnown := argKnown
		switch {
		case !argKnown && (strings.HasPrefix(arg, "--repo=") || strings.HasPrefix(arg, "-R")):
			return githubRepositoryIdentity{}, true, false
		case argKnown && ghRepositoryFlagTakesValue(arg):
			present = true
			i++
			if i >= len(args) || i >= len(known) || !known[i] {
				return githubRepositoryIdentity{}, true, false
			}
			value = args[i]
		case argKnown && strings.HasPrefix(arg, "--repo="):
			present = true
			value = strings.TrimPrefix(arg, "--repo=")
		case argKnown && strings.HasPrefix(arg, "-R") && len(arg) > 2:
			present = true
			value = arg[2:]
		default:
			continue
		}
		if !valueKnown {
			return githubRepositoryIdentity{}, true, false
		}
		if !defaultHostKnown && strings.Count(value, "/") == 1 {
			return githubRepositoryIdentity{}, true, false
		}
		identity, ok := parseGitHubRepositorySelector(value, defaultHost)
		if !ok {
			return githubRepositoryIdentity{}, true, false
		}
		if selected.String() != "" && selected.key() != identity.key() {
			return githubRepositoryIdentity{}, true, false
		}
		selected = identity
	}
	return selected, present, !present || selected.String() != ""
}

func parseGitHubRepositorySelector(value, defaultHost string) (githubRepositoryIdentity, bool) {
	parts := strings.Split(value, "/")
	host := defaultHost
	if len(parts) == 3 {
		host = parts[0]
		parts = parts[1:]
	}
	if len(parts) != 2 {
		return githubRepositoryIdentity{}, false
	}
	normalizedHost, err := normalizeGitHubHost(host)
	if err != nil {
		return githubRepositoryIdentity{}, false
	}
	owner, name, err := normalizeGitHubRepositoryName(parts[0] + "/" + parts[1])
	if err != nil {
		return githubRepositoryIdentity{}, false
	}
	return githubRepositoryIdentity{Host: normalizedHost, Owner: owner, Name: name}, true
}

func parseGitHubRemoteRepository(remote string) (githubRepositoryIdentity, bool) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return githubRepositoryIdentity{}, false
	}
	var host, repositoryPath string
	if strings.Contains(remote, "://") {
		parsed, err := url.Parse(remote)
		if err != nil || parsed.Hostname() == "" || parsed.Scheme == "file" {
			return githubRepositoryIdentity{}, false
		}
		host = strings.ToLower(parsed.Hostname())
		if port := parsed.Port(); port != "" {
			host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		repositoryPath = strings.TrimPrefix(parsed.Path, "/")
	} else {
		separator := strings.Index(remote, ":")
		if separator <= 0 || separator+1 >= len(remote) {
			return githubRepositoryIdentity{}, false
		}
		host = remote[:separator]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		repositoryPath = remote[separator+1:]
	}
	repositoryPath = strings.TrimPrefix(repositoryPath, "/")
	parts := strings.Split(repositoryPath, "/")
	if len(parts) != 2 {
		return githubRepositoryIdentity{}, false
	}
	parts[1] = strings.TrimSuffix(parts[1], ".git")
	identity, ok := parseGitHubRepositorySelector(host+"/"+parts[0]+"/"+parts[1], defaultGitHubHost)
	return identity, ok
}

func gitHubRemoteRepositories(cwd string) []githubRepositoryIdentity {
	output, err := gitCommand(cwd, "remote", "-v").Output()
	if err != nil {
		return nil
	}
	identities := make([]githubRepositoryIdentity, 0)
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		identity, ok := parseGitHubRemoteRepository(fields[1])
		if !ok || seen[identity.key()] {
			continue
		}
		seen[identity.key()] = true
		identities = append(identities, identity)
	}
	return identities
}

func (a *analyzer) blocksGitHubPullRequestCreation(identity githubRepositoryIdentity) bool {
	for _, block := range a.githubPullRequestCreateBlocks {
		blocked, ok := block.repositoryIdentity()
		if ok && blocked.key() == identity.key() {
			return true
		}
	}
	return false
}

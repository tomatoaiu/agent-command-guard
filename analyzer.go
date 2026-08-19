package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type Decision string

const (
	Allow  Decision = "allow"
	Review Decision = "review"
	Block  Decision = "block"
)

type Finding struct {
	Decision Decision `json:"decision"`
	RuleID   string   `json:"rule_id"`
	Message  string   `json:"message"`
	Command  string   `json:"command,omitempty"`
	Target   string   `json:"target,omitempty"`
}

type Result struct {
	Decision Decision  `json:"decision"`
	Message  string    `json:"message,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type analyzer struct {
	cwd                              string
	home                             string
	shell                            ShellDialect
	language                         string
	protectedBranches                []string
	protectedBranchExceptions        []GitProtectedBranchException
	protectedGitExceptionEligibility protectedGitExceptionEligibility
	suppressions                     []Suppression
	assignments                      map[string]string
	findings                         []Finding
}

func Analyze(command, cwd string) Result {
	return AnalyzeWithConfig(command, cwd, Config{})
}

func AnalyzeWithConfig(command, cwd string, config Config) Result {
	return AnalyzeWithConfigAndShell(command, cwd, config, ShellAuto)
}

func AnalyzeWithConfigAndShell(command, cwd string, config Config, shell ShellDialect) Result {
	if strings.TrimSpace(command) == "" {
		return Result{Decision: Allow}
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if rule := config.match(command, cwd); rule != nil {
		message := customRuleMessage(config.Output.Language, rule.ID)
		finding := Finding{Decision: rule.Action, RuleID: rule.ID, Message: message, Command: strings.TrimSpace(command), Target: cwd}
		return Result{Decision: rule.Action, Message: message, Findings: []Finding{finding}}
	}
	shell = shell.resolved()
	a := &analyzer{
		cwd:                       cwd,
		home:                      userHomeDir(),
		shell:                     shell,
		language:                  config.Output.Language,
		protectedBranches:         config.Git.ProtectedBranches,
		protectedBranchExceptions: config.Git.ProtectedBranchExceptions,
		suppressions:              config.Suppressions,
	}
	if shell == ShellPowerShell {
		a.analyzePowerShellSource(command, 0)
	} else {
		a.analyzePOSIXSource(command, 0)
	}
	return a.result()
}

func (a *analyzer) analyzePOSIXSource(source string, depth int) {
	if depth > 4 {
		a.add(Review, "nested-shell-depth", "shell", "")
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "hook")
	if err != nil {
		if containsRiskLexeme(source) {
			a.add(Review, "shell-parse-risk", "shell", "")
		}
		return
	}
	previousEligibility := a.protectedGitExceptionEligibility
	a.protectedGitExceptionEligibility = eligiblePOSIXProtectedGitException(file, depth, a.home)
	defer func() { a.protectedGitExceptionEligibility = previousEligibility }()
	// Assignments are scoped to the input being parsed. A nested payload does
	// not inherit them, which keeps an unresolved name dynamic rather than
	// resolving it from an unrelated scope.
	previousAssignments := a.assignments
	a.assignments = literalAssignments(file, a.home)
	defer func() { a.assignments = previousAssignments }()
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			a.inspectPOSIXCall(node, depth)
		case *syntax.Redirect:
			a.inspectRedirect(node)
		case *syntax.FuncDecl:
			if forkBombDeclaration(node.Name.Value) {
				a.add(Block, "fork-bomb", node.Name.Value, "")
			}
		case *syntax.DeclClause:
			a.inspectDeclClause(node)
		case *syntax.BinaryCmd:
			if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
				a.inspectPipeline(node)
			}
		}
		return true
	})
}

func eligiblePOSIXProtectedGitException(file *syntax.File, depth int, home string) protectedGitExceptionEligibility {
	if depth != 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	if len(file.Stmts) != 1 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionCompoundCommand}
	}
	statement := file.Stmts[0]
	if binary, ok := statement.Cmd.(*syntax.BinaryCmd); ok {
		switch binary.Op {
		case syntax.Pipe, syntax.PipeAll:
			return protectedGitExceptionEligibility{Reason: protectedGitExceptionPipeline}
		default:
			return protectedGitExceptionEligibility{Reason: protectedGitExceptionCompoundCommand}
		}
	}
	if len(statement.Redirs) > 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionRedirection}
	}
	if statement.Negated || statement.Background || statement.Coprocess {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	command := evalWord(call.Args[0], home, nil)
	if !command.Known {
		return protectedGitExceptionEligibility{}
	}
	if normalizeCommandName(command.Value) != "git" {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	callCount := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.CallExpr); ok {
			callCount++
		}
		return true
	})
	if callCount != 1 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	return protectedGitExceptionEligibility{Eligible: true, Reason: protectedGitExceptionEligible}
}

// "export FOO=bar" is a declaration rather than a call, so it never reaches
// inspectCommand. "declare", "local", "readonly", and "typeset" parse the same
// way; only "export" reaches beyond the current shell.
func (a *analyzer) inspectDeclClause(decl *syntax.DeclClause) {
	if decl.Variant == nil || decl.Variant.Value != "export" {
		return
	}
	for _, assign := range decl.Args {
		a.inspectAssign(assign, "export")
	}
}

// A prefix assignment ("PATH=/tmp/evil some-command") redirects the command it
// prefixes just as an export redirects the rest of the session.
func (a *analyzer) inspectAssign(assign *syntax.Assign, command string) {
	if assign == nil || assign.Name == nil || assign.Value == nil {
		return
	}
	valueKnown := evalWord(assign.Value, a.home, a.assignments).Known
	if rule := environmentOverrideRule(assign.Name.Value, valueKnown); rule != "" {
		a.add(Review, rule, command, "")
	}
}

func (a *analyzer) inspectEnvAssignments(args []string, known []bool) {
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, _, ok := strings.Cut(arg, "=")
		if !ok {
			// The first argument without "=" is the command env runs.
			return
		}
		valueKnown := i < len(known) && known[i]
		if rule := environmentOverrideRule(name, valueKnown); rule != "" {
			a.add(Review, rule, "env", "")
		}
	}
}

func (a *analyzer) inspectPOSIXCall(call *syntax.CallExpr, depth int) {
	for _, assign := range call.Assigns {
		a.inspectAssign(assign, "assignment")
	}
	if len(call.Args) == 0 {
		return
	}
	words := make([]wordValue, 0, len(call.Args))
	for _, arg := range call.Args {
		words = append(words, evalWord(arg, a.home, a.assignments))
	}
	if !words[0].Known {
		a.add(Review, "dynamic-command-name", "dynamic", "")
		return
	}
	// Command substitution has to be seen before the arguments are flattened
	// to strings, because flattening only records that a value was dynamic,
	// not that it came from running something.
	if name := normalizeCommandName(words[0].Value); dnsLookupCommand(name) {
		for _, arg := range call.Args[1:] {
			if wordHasCommandSubstitution(arg) {
				a.add(Block, "dns-exfiltration", name, "")
				break
			}
		}
	}
	argv := make([]string, len(words))
	known := make([]bool, len(words))
	for i, word := range words {
		argv[i], known[i] = word.Value, word.Known
	}
	// env carries its assignments as ordinary arguments, and unwrapCommand
	// drops them on the way to the wrapped command, so they are read here
	// while they are still visible.
	if normalizeCommandName(argv[0]) == "env" {
		a.inspectEnvAssignments(argv[1:], known[1:])
	}
	argv, known = unwrapCommand(argv, known)
	a.inspectCommand(argv, known, depth)
}

func (a *analyzer) inspectCommand(argv []string, known []bool, depth int) {
	if len(argv) == 0 {
		return
	}
	command := normalizeCommandName(argv[0])
	args := argv[1:]
	argKnown := known[1:]

	if isShell(command) {
		if index := shellCodeIndex(args); index >= 0 {
			if index < len(argKnown) && argKnown[index] {
				a.analyzePOSIXSource(args[index], depth+1)
			} else {
				a.add(Review, "dynamic-shell-code", command, "")
			}
		}
	}
	if inlineInterpreterCode(command, args) {
		// Read the payload before raising the review, because the review can be
		// suppressed and a protected path inside the payload must not be.
		a.inspectInterpreterPayloads(command, args, argKnown)
		a.add(Review, "inline-interpreter-code", command, "")
	}
	if command == "xargs" && containsExecutionGateway(args) {
		if payload, ok := gatewayShellPayload(args, argKnown); ok {
			a.analyzePOSIXSource(payload, depth+1)
		} else {
			a.add(Review, "indirect-execution-gateway", command, "")
		}
	}
	if command == "find" {
		if findExecutesGateway(args) {
			a.add(Review, "indirect-execution-gateway", command, "")
		}
		for _, nested := range findExecCommands(args, argKnown) {
			a.inspectCommand(nested.argv, nested.known, depth+1)
		}
		if containsAny(args, "-delete") {
			if target, ok := a.findDeletesDangerousRoot(args, argKnown); ok {
				a.add(Block, "recursive-delete-protected", command, target)
			} else {
				a.add(Review, "find-delete", command, "")
			}
		}
	}
	// mkfs and newfs come in one variant per filesystem, so they are matched
	// by prefix rather than named in the switch below.
	if destroysStorage(command) {
		a.add(Block, "destructive-storage-command", command, "")
	}
	// Publishing and host mounts cut across too many tools to sit in the
	// switch, where each would need its own case with the same body.
	if publishesPackage(command, args) {
		a.add(Block, "package-publish", command, "")
	}
	if publishesContainerArtifact(command, args) {
		a.add(Review, "artifact-publish", command, "")
	}
	if containerMountsHost(command, args) {
		a.add(Review, "container-host-mount", command, "")
	}

	switch command {
	case "rm":
		a.inspectRM(args, argKnown)
	case "unlink":
		for i, arg := range args {
			if i < len(argKnown) && argKnown[i] && a.protectedPath(arg) {
				a.add(Block, "protected-delete", command, a.normalizePath(arg))
			}
		}
	case "git":
		a.inspectGit(args, argKnown)
	case "sudo", "doas", "pkexec", "su":
		a.add(Block, "privilege-escalation", command, "")
	case "nvram":
		if !nvramReadsOnly(args, argKnown) {
			a.add(Block, "sensitive-system-command", command, "")
		}
	case "csrutil":
		if !csrutilReadsOnly(args, argKnown) {
			a.add(Block, "sensitive-system-command", command, "")
		}
	case "dscl":
		if !dsclReadsOnly(args, argKnown) {
			a.add(Block, "sensitive-system-command", command, "")
		}
	case "networksetup":
		if !networksetupReadsOnly(args, argKnown) {
			a.add(Block, "sensitive-system-command", command, "")
		}
	case "osascript", "security", "screencapture":
		a.add(Block, "sensitive-system-command", command, "")
	case "diskutil":
		if diskutilDestroys(args, argKnown) {
			a.add(Block, "destructive-storage-command", command, "")
		}
	case "hdiutil":
		if firstSubcommand(args) == "erase" {
			a.add(Block, "destructive-storage-command", command, "")
		}
	case "crontab":
		if containsAny(args, "-r") {
			a.add(Block, "scheduled-job-wipe", command, "")
		}
	case "chezmoi":
		if sub := firstSubcommand(args); sub == "destroy" || sub == "purge" {
			a.add(Block, "managed-state-destroy", command, "")
		}
	case "mise":
		if firstSubcommand(args) == "implode" {
			a.add(Block, "managed-state-destroy", command, "")
		}
	case "defaults":
		if firstSubcommand(args) == "delete" {
			a.add(Review, "system-preferences-delete", command, "")
		}
	case "launchctl":
		switch firstSubcommand(args) {
		case "reboot":
			a.add(Block, "system-shutdown", command, "")
		case "load", "unload", "bootstrap", "bootout", "remove", "enable", "disable":
			a.add(Review, "launch-service-change", command, "")
		}
	case "systemctl":
		switch firstSubcommand(args) {
		case "poweroff", "reboot", "halt", "kexec":
			a.add(Block, "system-shutdown", command, "")
		}
	case "shutdown", "reboot", "halt", "poweroff":
		a.add(Block, "system-shutdown", command, "")
	case "dd":
		if anyArgPrefix(args, "of=") {
			a.add(Block, "raw-write", command, "")
		}
	case "truncate", "shred":
		a.add(Block, "destructive-file-command", command, "")
	case "nc", "ncat", "netcat":
		a.add(Block, "raw-network-channel", command, "")
	case "curl":
		if curlUploadsFile(args) {
			a.add(Block, "file-upload", command, "")
		}
	case "wget":
		if containsAny(args, "--post-data", "--post-file", "--body-file") || anyArgPrefix(args, "--post-file=") || anyArgPrefix(args, "--body-file=") {
			a.add(Block, "file-upload", command, "")
		}
	case "scp", "sftp":
		if command == "sftp" || anyRemotePath(args) {
			if !a.inspectTransferSources(command, args, argKnown) {
				a.add(Review, "remote-file-transfer", command, "")
			}
		}
	case "rsync":
		if anyRemotePath(args) {
			if !a.inspectTransferSources(command, args, argKnown) {
				a.add(Review, "remote-file-transfer", command, "")
			}
		}
	case "rclone":
		if transferSubcommand(args) && anyRemotePath(args) {
			if !a.inspectTransferSources(command, args, argKnown) {
				a.add(Review, "remote-file-transfer", command, "")
			}
		}
	case "aws":
		if cloudStorageTransfer(args, "s3") {
			if !a.inspectTransferSources(command, args, argKnown) {
				a.add(Review, "cloud-storage-transfer", command, "")
			}
		}
	case "gsutil":
		if containsAny(args, "cp", "mv", "rsync") {
			if !a.inspectTransferSources(command, args, argKnown) {
				a.add(Review, "cloud-storage-transfer", command, "")
			}
		}
	case "az":
		if len(args) >= 3 && args[0] == "storage" && (args[1] == "blob" || args[1] == "file") && containsAny(args[2:], "upload", "upload-batch", "sync") {
			if !a.inspectTransferSources(command, args, argKnown) {
				a.add(Review, "cloud-storage-transfer", command, "")
			}
		}
	case "tar", "zip", "7z", "7zz", "ditto", "cpio":
		if target, ok := a.archiveSensitiveTarget(args, argKnown); ok {
			a.add(Block, "credential-archive", command, target)
		} else if archiveContainsProtectedPath(args, argKnown, a) {
			a.add(Review, "sensitive-archive", command, "")
		}
	case "docker", "podman":
		if containerPrune(args) {
			a.add(Review, "container-prune", command, "")
		}
	case "kubectl":
		if firstSubcommand(args) == "delete" {
			a.add(Review, "infrastructure-delete", command, "")
		}
	case "terraform", "tofu":
		if firstSubcommand(args) == "destroy" || containsAny(args, "-destroy") {
			a.add(Review, "infrastructure-delete", command, "")
		}
	case "helm":
		if sub := firstSubcommand(args); sub == "uninstall" || sub == "delete" {
			a.add(Review, "infrastructure-delete", command, "")
		}
	case "eval", "source", ".":
		a.add(Review, "dynamic-code-gateway", command, "")
	case "brew":
		if firstSubcommand(args) == "uninstall" || firstSubcommand(args) == "remove" || firstSubcommand(args) == "untap" {
			a.add(Review, "package-removal", command, "")
		}
	case "gh":
		if ghDestroys(args) {
			a.add(Block, "repository-administration", command, "")
		}
	case "open":
		if opensRemoteURL(args, argKnown) {
			a.add(Review, "browser-navigation", command, "")
		}
	case "chmod":
		if chmodGrantsWorldWrite(args, argKnown) {
			a.add(Block, "world-writable", command, "")
		}
		for i, arg := range args {
			if i < len(argKnown) && argKnown[i] && a.protectedPath(arg) {
				a.add(Block, "guard-self-protection", command, a.normalizePath(arg))
			}
		}
	case "chown":
		for i, arg := range args {
			if i < len(argKnown) && argKnown[i] && a.protectedPath(arg) {
				a.add(Block, "guard-self-protection", command, a.normalizePath(arg))
			}
		}
	case "ln":
		a.inspectSymlink(args, argKnown)
	case "tee":
		a.inspectWriteTargets(command, args, argKnown, false)
	case "cp", "mv", "install":
		a.inspectWriteTargets(command, args, argKnown, true)
	case "sed":
		if containsAny(args, "-i", "--in-place") || anyArgPrefix(args, "-i") || anyArgPrefix(args, "--in-place=") {
			a.inspectWriteTargets(command, args, argKnown, false)
		} else {
			a.inspectSensitiveReadArgs(command, args, argKnown)
		}
	case "cat", "head", "tail", "less", "more", "grep", "rg", "awk", "base64", "strings", "xxd", "od", "hexdump", "cut", "sort", "uniq", "wc", "jq", "yq", "openssl":
		a.inspectSensitiveReadArgs(command, args, argKnown)
	}
}

func archiveContainsProtectedPath(args []string, known []bool, a *analyzer) bool {
	for i, arg := range args {
		if i >= len(known) || !known[i] || strings.HasPrefix(arg, "-") {
			continue
		}
		if a.protectedPath(arg) {
			return true
		}
	}
	return false
}

func containerPrune(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if (args[i] == "system" || args[i] == "container" || args[i] == "volume" || args[i] == "image" || args[i] == "network" || args[i] == "builder") && args[i+1] == "prune" {
			return true
		}
	}
	return false
}

func anyRemotePath(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, "://") || strings.Contains(arg, ":") {
			return true
		}
	}
	return false
}

func transferSubcommand(args []string) bool {
	sub := firstSubcommand(args)
	return sub == "copy" || sub == "copyto" || sub == "move" || sub == "moveto" || sub == "sync" || sub == "bisync" || sub == "mount"
}

func cloudStorageTransfer(args []string, service string) bool {
	return len(args) >= 2 && args[0] == service && (args[1] == "cp" || args[1] == "mv" || args[1] == "sync")
}

func (a *analyzer) inspectSymlink(args []string, known []bool) {
	symlink := false
	for _, arg := range args {
		if arg == "--symbolic" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(strings.TrimPrefix(arg, "-"), "s") {
			symlink = true
			break
		}
	}
	if !symlink {
		return
	}
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if i >= len(known) || !known[i] {
			a.add(Review, "dynamic-protected-symlink", "ln", "dynamic")
			return
		}
		if a.protectedPath(arg) {
			a.add(Block, "protected-symlink", "ln", a.normalizePath(arg))
		}
		return
	}
}

func (a *analyzer) inspectSensitiveReadArgs(command string, args []string, known []bool) {
	for i, arg := range args {
		if i < len(known) && known[i] && a.sensitiveReadPath(arg) {
			a.add(Block, "sensitive-shell-read", command, a.normalizePath(arg))
		}
	}
}

func (a *analyzer) inspectWriteTargets(command string, args []string, known []bool, lastOnly bool) {
	indices := make([]int, 0)
	for i, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			indices = append(indices, i)
		}
	}
	if lastOnly && len(indices) > 0 {
		indices = indices[len(indices)-1:]
	}
	for _, i := range indices {
		if i < len(known) && known[i] && a.protectedPath(args[i]) {
			a.add(Block, "guard-self-protection", command, a.normalizePath(args[i]))
		}
	}
}

func (a *analyzer) inspectRM(args []string, known []bool) {
	recursive := false
	targets := make([]int, 0)
	endOptions := false
	for i, arg := range args {
		if !endOptions && arg == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(arg, "-") {
			if arg == "--recursive" || strings.Contains(strings.TrimPrefix(arg, "-"), "r") || strings.Contains(strings.TrimPrefix(arg, "-"), "R") {
				recursive = true
			}
			continue
		}
		targets = append(targets, i)
	}
	if !recursive {
		for _, index := range targets {
			if index < len(known) && known[index] {
				if a.protectedPath(args[index]) {
					a.add(Block, "protected-delete", "rm", a.normalizePath(args[index]))
				} else if isSigningKey(args[index]) {
					a.add(Review, "signing-key-delete", "rm", a.normalizePath(args[index]))
				}
			}
		}
		return
	}
	for _, index := range targets {
		if index >= len(known) || !known[index] {
			a.add(Review, "dynamic-recursive-delete", "rm", "dynamic")
			continue
		}
		target := a.normalizePath(args[index])
		if a.dangerousDeleteTarget(target) {
			a.add(Block, "recursive-delete-protected", "rm", target)
		}
	}
}

// SafeTempCleanup recognizes the narrow recursive-deletion shape that Codex
// may auto-approve. It intentionally accepts only one literal rm invocation;
// normal analysis remains responsible for every broader command shape.
func SafeTempCleanup(source, cwd string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "permission")
	if err != nil || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Negated || stmt.Background || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) < 2 {
		return false
	}
	words := literalWords(call.Args, userHomeDir(), nil)
	for _, word := range words {
		if !word.Known {
			return false
		}
	}
	if normalizeCommandName(words[0].Value) != "rm" {
		return false
	}
	recursive := false
	targets := make([]string, 0)
	endOptions := false
	for _, word := range words[1:] {
		arg := word.Value
		if !endOptions && arg == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(arg, "-") {
			if arg == "--recursive" || strings.ContainsAny(strings.TrimPrefix(arg, "-"), "rR") {
				recursive = true
			}
			continue
		}
		targets = append(targets, arg)
	}
	if !recursive || len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if !safeTempDeleteTarget(target) {
			return false
		}
	}
	return true
}

func safeTempDeleteTarget(target string) bool {
	if !filepath.IsAbs(target) || strings.ContainsAny(target, "*?[") {
		return false
	}
	target = filepath.Clean(target)
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolvedTarget := resolvePathSymlinks(target)
	tempRoots := []string{os.TempDir(), "/tmp", "/private/tmp"}
	withinTemp := false
	for _, root := range tempRoots {
		root = resolvePathSymlinks(filepath.Clean(root))
		if target != root && resolvedTarget != root && filepath.Dir(resolvedTarget) == root {
			withinTemp = true
			break
		}
	}
	if !withinTemp {
		return false
	}
	if _, err := os.Lstat(filepath.Join(target, ".git")); err == nil {
		return false
	}
	command := gitCommand(target, "rev-parse", "--show-toplevel")
	if output, err := command.Output(); err == nil {
		repositoryRoot := resolvePathSymlinks(strings.TrimSpace(string(output)))
		if repositoryRoot == resolvedTarget {
			return false
		}
	}
	return true
}

func (a *analyzer) inspectPipeline(pipeline *syntax.BinaryCmd) {
	leftSource := statementHasSensitiveSource(pipeline.X, a)
	rightSink := statementHasNetworkOrShellSink(pipeline.Y)
	if leftSource && rightSink {
		a.add(Block, "sensitive-pipeline", "pipeline", "")
	}
	if statementHasNetworkSource(pipeline.X) && statementHasShellSink(pipeline.Y) {
		a.add(Block, "download-to-shell", "pipeline", "")
	}
	if statementHasDecoderSource(pipeline.X) && statementHasShellSink(pipeline.Y) {
		a.add(Block, "decoded-to-shell", "pipeline", "")
	}
}

func statementHasSensitiveSource(stmt *syntax.Stmt, a *analyzer) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := literalWords(call.Args, a.home, a.assignments)
		if len(words) == 0 {
			return true
		}
		command := normalizeCommandName(words[0].Value)
		if command == "security" || command == "env" || command == "printenv" {
			found = true
			return false
		}
		if command == "cat" || command == "head" || command == "tail" || command == "sed" {
			for _, word := range words[1:] {
				if word.Known && a.sensitiveReadPath(word.Value) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func statementHasNetworkOrShellSink(stmt *syntax.Stmt) bool {
	return statementHasCommand(stmt, func(command string) bool {
		return command == "curl" || command == "wget" || command == "nc" || command == "ncat" || command == "netcat" || command == "ssh" || isShell(command)
	})
}

func statementHasNetworkSource(stmt *syntax.Stmt) bool {
	return statementHasCommand(stmt, func(command string) bool { return command == "curl" || command == "wget" })
}

func statementHasShellSink(stmt *syntax.Stmt) bool {
	return statementHasCommand(stmt, isShell)
}

func statementHasDecoderSource(stmt *syntax.Stmt) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := literalWords(call.Args, userHomeDir(), nil)
		if len(words) == 0 || !words[0].Known {
			return true
		}
		command := normalizeCommandName(words[0].Value)
		args := make([]string, 0, len(words)-1)
		for _, word := range words[1:] {
			if !word.Known {
				return true
			}
			args = append(args, word.Value)
		}
		if decoderCommand(command, args) {
			found = true
			return false
		}
		return true
	})
	return found
}

func decoderCommand(command string, args []string) bool {
	switch command {
	case "base64":
		return containsAny(args, "-d", "-D", "--decode")
	case "xxd":
		return containsAny(args, "-r", "--revert")
	case "openssl":
		return containsAny(args, "-d", "-decrypt")
	case "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz":
		return containsAny(args, "-d", "--decompress") || command == "gunzip" || command == "bunzip2" || command == "unxz"
	default:
		return false
	}
}

var pythonCommandPattern = regexp.MustCompile(`^python[0-9.]*$`)

// The flags that make an interpreter run the next argument as a program.
// Shared with inlineInterpreterPayloads so that the check and the extraction
// cannot drift apart.
func inlineInterpreterEvalFlags(command string) []string {
	switch {
	case pythonCommandPattern.MatchString(command):
		return []string{"-c"}
	case command == "node" || command == "bun":
		return []string{"-e", "--eval", "-p", "--print"}
	case command == "ruby":
		return []string{"-e"}
	case command == "perl":
		return []string{"-e", "-E"}
	case command == "php":
		return []string{"-r"}
	case command == "lua" || strings.HasPrefix(command, "lua5."):
		return []string{"-e"}
	}
	return nil
}

func inlineInterpreterCode(command string, args []string) bool {
	if command == "deno" && firstSubcommand(args) == "eval" {
		return true
	}
	return containsAny(args, inlineInterpreterEvalFlags(command)...)
}

func containsExecutionGateway(args []string) bool {
	for _, arg := range args {
		command := normalizeCommandName(arg)
		if isShell(command) || inlineInterpreterName(command) {
			return true
		}
	}
	return false
}

// gatewayShellPayload returns the shell code xargs would run, when the source
// text fixes that code. Analyzing it reports what the payload actually does
// instead of stopping at the gateway, which both clears an ordinary payload and
// raises a dangerous one to its own decision.
//
// An interpreter gateway such as `python3 -c` is not shell code and is left to
// the existing review. So is a payload holding the replacement string, since
// xargs substitutes data read at run time into it.
func gatewayShellPayload(args []string, known []bool) (string, bool) {
	replacement := xargsReplacement(args)
	for i, arg := range args {
		if !isShell(normalizeCommandName(arg)) {
			continue
		}
		rest, restKnown := args[i+1:], known[i+1:]
		index := shellCodeIndex(rest)
		if index < 0 || index >= len(restKnown) || !restKnown[index] {
			return "", false
		}
		payload := rest[index]
		if replacement != "" && strings.Contains(payload, replacement) {
			return "", false
		}
		return payload, true
	}
	return "", false
}

// xargsReplacement returns the token xargs substitutes with each input item, or
// an empty string when the invocation does not use one.
func xargsReplacement(args []string) string {
	for i, arg := range args {
		switch {
		case arg == "-I" || arg == "-i" || arg == "--replace":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "-I") && len(arg) > 2:
			return arg[2:]
		case strings.HasPrefix(arg, "--replace="):
			return strings.TrimPrefix(arg, "--replace=")
		}
	}
	return ""
}

func findExecutesGateway(args []string) bool {
	for i, arg := range args {
		if (arg == "-exec" || arg == "-execdir" || arg == "-ok" || arg == "-okdir") && i+1 < len(args) {
			command := normalizeCommandName(args[i+1])
			return isShell(command) || inlineInterpreterName(command)
		}
	}
	return false
}

// findExecCommand is one command that find runs itself, recovered from the
// arguments between an -exec style primary and the ";" or "+" that closes it.
type findExecCommand struct {
	argv  []string
	known []bool
}

// findExecCommands recovers the commands a find invocation runs, so that each
// one is inspected like a command written on its own. Without this, "find .
// -exec rm -rf {} +" passes untouched while the equivalent "find . -delete" is
// reviewed, even though both delete whatever the traversal reaches.
//
// The "{}" placeholder is reported as unknown because find substitutes a path
// at run time. A recursive deletion built on it therefore lands on the same
// dynamic-target reporting as "rm -rf $VAR", while a literal path written
// alongside it stays resolvable and keeps its protected-path checks.
func findExecCommands(args []string, known []bool) []findExecCommand {
	commands := make([]findExecCommand, 0)
	for i := 0; i < len(args); i++ {
		if args[i] != "-exec" && args[i] != "-execdir" && args[i] != "-ok" && args[i] != "-okdir" {
			continue
		}
		argv := make([]string, 0)
		argvKnown := make([]bool, 0)
		for j := i + 1; j < len(args); j++ {
			i = j
			if args[j] == ";" || args[j] == "+" {
				break
			}
			argv = append(argv, args[j])
			argvKnown = append(argvKnown, j < len(known) && known[j] && !strings.Contains(args[j], "{}"))
		}
		if len(argv) > 0 {
			commands = append(commands, findExecCommand{argv: argv, known: argvKnown})
		}
	}
	return commands
}

func inlineInterpreterName(command string) bool {
	return regexp.MustCompile(`^python[0-9.]*$`).MatchString(command) || containsAny([]string{command}, "node", "ruby", "perl", "php", "lua", "deno", "bun") || strings.HasPrefix(command, "lua5.")
}

func statementHasCommand(stmt *syntax.Stmt, predicate func(string) bool) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		value := evalWord(call.Args[0], userHomeDir(), nil)
		if value.Known && predicate(normalizeCommandName(value.Value)) {
			found = true
			return false
		}
		return true
	})
	return found
}

func literalWords(words []*syntax.Word, home string, assignments map[string]string) []wordValue {
	result := make([]wordValue, 0, len(words))
	for _, word := range words {
		result = append(result, evalWord(word, home, assignments))
	}
	return result
}

func (a *analyzer) inspectGit(args []string, known []bool) {
	globalsSafeForException := safeGitGlobalsForException(args, known)
	args, known, gitCWD, cwdKnown := stripGitGlobals(args, known, a.cwd)
	if len(args) == 0 || !known[0] {
		return
	}
	sub := args[0]
	rest := args[1:]
	restKnown := known[1:]
	switch sub {
	case "branch":
		if !cwdKnown {
			a.add(Review, "git-dynamic-working-directory", "git", "dynamic")
			return
		}
		a.inspectGitBranch(rest, restKnown, gitCWD)
	case "reset":
		if containsAny(rest, "--hard") {
			a.add(Block, "git-reset-hard", "git", "")
		}
	case "clean":
		if hasForceFlag(rest) {
			a.add(Review, "git-clean-force", "git", "")
		}
	case "stash":
		if len(rest) > 0 && (rest[0] == "drop" || rest[0] == "clear") {
			a.add(Review, "git-stash-delete", "git", "")
		}
	case "push":
		if !cwdKnown {
			a.add(Review, "git-dynamic-working-directory", "git", "dynamic")
			return
		}
		a.inspectGitPush(rest, restKnown, gitCWD, globalsSafeForException)
	case "commit":
		if !cwdKnown {
			a.add(Review, "git-dynamic-working-directory", "git", "dynamic")
			return
		}
		if branch := currentBranch(gitCWD); a.protectedBranch(branch, gitCWD) {
			if !globalsSafeForException || !safeProtectedCommitArguments(rest, restKnown) {
				a.add(Block, "protected-branch-direct-commit", "git", branch)
				return
			}
			if !a.matchesProtectedBranchException(gitOperationCommit, gitCWD, branch, "") {
				a.add(Block, "protected-branch-direct-commit", "git", branch)
				return
			}
			if a.protectedGitExceptionEligibility.Eligible {
				a.add(Allow, "protected-branch-exception", "git", branch)
				return
			}
			a.add(Block, protectedGitExceptionRuleID(a.protectedGitExceptionEligibility.Reason), "git", branch)
		}
	}
}

func (a *analyzer) inspectGitBranch(args []string, known []bool, gitCWD string) {
	deleting := containsAny(args, "-d", "-D", "--delete")
	if !deleting {
		return
	}
	if !allKnown(known) {
		a.add(Review, "git-dynamic-branch-delete", "git", "dynamic")
		return
	}
	for _, branch := range gitOperands(args) {
		if a.protectedBranch(branch, gitCWD) {
			a.add(Block, "protected-branch-delete", "git", branch)
		}
	}
}

func (a *analyzer) inspectGitPush(args []string, known []bool, gitCWD string, globalsSafeForException bool) {
	if !allKnown(known) {
		a.add(Review, "git-dynamic-push-ref", "git", "dynamic")
		return
	}
	parsed := parseGitPushArgs(args)
	if parsed.bulk {
		a.add(Block, "protected-branch-bulk-push", "git", "all")
		return
	}
	deleting := containsAny(args, "--delete", "-d")
	if !deleting {
		for _, refspec := range parsed.refspecs {
			if strings.HasPrefix(refspec, ":") {
				deleting = true
			}
		}
	}

	targets := pushTargets(parsed.refspecs, deleting)
	if deleting {
		if len(targets) == 0 {
			a.add(Review, "git-remote-delete-unknown", "git", "dynamic")
			return
		}
		for _, target := range targets {
			target = strings.TrimPrefix(target, ":")
			if target == "tag" || strings.HasPrefix(target, "refs/tags/") {
				a.add(Review, "git-remote-tag-delete", "git", target)
			} else if a.protectedBranch(strings.TrimPrefix(target, "refs/heads/"), gitCWD) {
				a.add(Block, "protected-remote-branch-delete", "git", target)
			}
		}
		return
	}
	// An initial push is necessary to create the first remote branch. Only
	// bypass protected-branch matching when gitCWD is a valid repository whose
	// local history is demonstrably empty; non-repositories remain protected.
	initialPush := emptyGitHistory(gitCWD)

	if len(targets) == 0 {
		targets = []string{currentBranch(gitCWD)}
	}
	for _, target := range targets {
		target = pushedBranch(target, currentBranch(gitCWD))
		if !initialPush && target != "" && a.protectedBranch(target, gitCWD) {
			if !globalsSafeForException || !exactProtectedPush(parsed, target) {
				a.add(Block, "protected-branch-push", "git", target)
				return
			}
			if !a.matchesProtectedBranchException(gitOperationPush, gitCWD, target, parsed.remote) {
				a.add(Block, "protected-branch-push", "git", target)
				return
			}
			if a.protectedGitExceptionEligibility.Eligible {
				a.add(Allow, "protected-branch-exception", "git", target)
				continue
			}
			a.add(Block, protectedGitExceptionRuleID(a.protectedGitExceptionEligibility.Reason), "git", target)
			return
		}
	}
	if hasUnsafeForce(args) || hasForcedRefspec(parsed.refspecs) {
		a.add(Review, "git-force-push", "git", "")
	}
}

func hasForcedRefspec(refspecs []string) bool {
	for _, refspec := range refspecs {
		if strings.HasPrefix(refspec, "+") {
			return true
		}
	}
	return false
}

type gitPushArgs struct {
	remote           string
	refspecs         []string
	bulk             bool
	hasOptions       bool
	repositoryOption bool
}

func parseGitPushArgs(args []string) gitPushArgs {
	operands := make([]string, 0, len(args))
	result := gitPushArgs{}
	endOptions := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !endOptions && arg == "--" {
			endOptions = true
			result.hasOptions = true
			continue
		}
		if !endOptions {
			if arg == "--all" || arg == "--mirror" {
				result.bulk = true
				result.hasOptions = true
				return result
			}
			if arg == "--repo" {
				result.repositoryOption = true
				result.hasOptions = true
				if i+1 < len(args) {
					i++
				}
				continue
			}
			if strings.HasPrefix(arg, "--repo=") {
				result.repositoryOption = true
				result.hasOptions = true
				continue
			}
			if pushOptionTakesValue(arg) {
				result.hasOptions = true
				if i+1 < len(args) {
					i++
				}
				continue
			}
			if strings.HasPrefix(arg, "-") {
				result.hasOptions = true
				continue
			}
		}
		operands = append(operands, arg)
	}
	if result.repositoryOption {
		result.refspecs = operands
		return result
	}
	if len(operands) > 0 {
		result.remote = operands[0]
	}
	if len(operands) > 1 {
		result.refspecs = operands[1:]
	}
	return result
}

func pushOptionTakesValue(arg string) bool {
	switch arg {
	case "--receive-pack", "--exec", "-o", "--push-option":
		return true
	default:
		return false
	}
}

func allKnown(known []bool) bool {
	for _, value := range known {
		if !value {
			return false
		}
	}
	return true
}

func gitOperands(args []string) []string {
	result := make([]string, 0, len(args))
	endOptions := false
	for _, arg := range args {
		if !endOptions && arg == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(arg, "-") {
			continue
		}
		result = append(result, arg)
	}
	return result
}

func pushTargets(refspecs []string, deleting bool) []string {
	targets := refspecs
	if deleting && len(targets) > 1 && targets[0] == "tag" {
		return []string{"refs/tags/" + targets[1]}
	}
	return targets
}

func pushedBranch(refspec, current string) string {
	refspec = strings.TrimPrefix(refspec, "+")
	if index := strings.LastIndex(refspec, ":"); index >= 0 {
		refspec = refspec[index+1:]
	}
	if refspec == "HEAD" || refspec == "@" {
		refspec = current
	}
	return strings.TrimPrefix(refspec, "refs/heads/")
}

func (a *analyzer) protectedBranch(branch, gitCWD string) bool {
	if branch == "" {
		return false
	}
	patterns := []string{"main", "master"}
	if remoteDefault := defaultBranch(gitCWD); remoteDefault != "" {
		patterns = append(patterns, remoteDefault)
	}
	patterns = append(patterns, a.protectedBranches...)
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, branch); matched {
			return true
		}
	}
	return false
}

func (a *analyzer) inspectRedirect(redir *syntax.Redirect) {
	switch redir.Op {
	case syntax.RdrIn, syntax.RdrInOut:
		word := evalWord(redir.Word, a.home, a.assignments)
		if word.Known && a.sensitiveReadPath(word.Value) {
			a.add(Block, "sensitive-input-redirection", "redirect", a.normalizePath(word.Value))
		}
		return
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
	default:
		return
	}
	word := evalWord(redir.Word, a.home, a.assignments)
	if !word.Known {
		return
	}
	if isDevicePath(word.Value) {
		a.add(Block, "device-write", "redirect", word.Value)
		return
	}
	if a.protectedPath(word.Value) {
		a.add(Block, "protected-redirection", "redirect", a.normalizePath(word.Value))
	}
}

func (a *analyzer) result() Result {
	decision := Allow
	for _, finding := range a.findings {
		if severity(finding.Decision) > severity(decision) {
			decision = finding.Decision
		}
	}
	sort.SliceStable(a.findings, func(i, j int) bool {
		return severity(a.findings[i].Decision) > severity(a.findings[j].Decision)
	})
	message := ""
	if len(a.findings) > 0 {
		message = a.findings[0].Message
		if a.findings[0].Target != "" {
			message += targetMessage(a.language, a.findings[0].Target)
		}
		message += ruleReference(a.language, a.findings[0].RuleID)
	}
	return Result{Decision: decision, Message: message, Findings: a.findings}
}

func (a *analyzer) add(decision Decision, ruleID, command, target string) {
	if a.suppresses(decision, ruleID, command) {
		return
	}
	finding := Finding{Decision: decision, RuleID: ruleID, Command: command, Target: target}
	finding.Message = findingMessage(a.language, finding)
	a.findings = append(a.findings, finding)
}

func severity(decision Decision) int {
	switch decision {
	case Block:
		return 2
	case Review:
		return 1
	default:
		return 0
	}
}

type wordValue struct {
	Value string
	Known bool
}

func evalWord(word *syntax.Word, home string, assignments map[string]string) wordValue {
	var builder strings.Builder
	expand := func(expansion *syntax.ParamExp) (string, bool) {
		if expansion.Param != nil && expansion.Param.Value == "HOME" && !expansion.Excl && expansion.Exp == nil {
			return home, true
		}
		return assignedValue(expansion, assignments)
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			builder.WriteString(part.Value)
		case *syntax.SglQuoted:
			builder.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, nested := range part.Parts {
				switch nested := nested.(type) {
				case *syntax.Lit:
					builder.WriteString(nested.Value)
				case *syntax.SglQuoted:
					builder.WriteString(nested.Value)
				case *syntax.ParamExp:
					value, ok := expand(nested)
					if !ok {
						return wordValue{Known: false}
					}
					builder.WriteString(value)
				default:
					return wordValue{Known: false}
				}
			}
		case *syntax.ParamExp:
			value, ok := expand(part)
			if !ok {
				return wordValue{Known: false}
			}
			builder.WriteString(value)
		default:
			return wordValue{Known: false}
		}
	}
	value := builder.String()
	if value == "~" {
		value = home
	} else if strings.HasPrefix(value, "~/") {
		value = filepath.Join(home, value[2:])
	}
	return wordValue{Value: value, Known: true}
}

func unwrapCommand(argv []string, known []bool) ([]string, []bool) {
	for len(argv) > 0 {
		switch normalizeCommandName(argv[0]) {
		case "command", "exec", "nohup", "time":
			argv, known = argv[1:], known[1:]
		case "env":
			argv, known = argv[1:], known[1:]
			for len(argv) > 0 && (strings.Contains(argv[0], "=") || strings.HasPrefix(argv[0], "-")) {
				argv, known = argv[1:], known[1:]
			}
		default:
			return argv, known
		}
	}
	return argv, known
}

func (a *analyzer) normalizePath(path string) string {
	if path == "~" {
		path = a.home
	} else if strings.HasPrefix(path, "~/") || a.shell == ShellPowerShell && strings.HasPrefix(path, `~\`) {
		path = filepath.Join(a.home, path[2:])
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.cwd, path)
	}
	return filepath.Clean(path)
}

func (a *analyzer) protectedPath(path string) bool {
	normalized := a.normalizePath(path)
	resolved := resolvePathSymlinks(normalized)
	protected := []string{
		filepath.Join(a.home, ".ssh"), filepath.Join(a.home, ".gnupg"),
		filepath.Join(a.home, ".aws"), filepath.Join(a.home, ".azure"),
		filepath.Join(a.home, ".gcloud"),
	}
	// Agent control roots are shared with the direct file policy so that a shell
	// redirection cannot reach a path that Write/Edit refuses.
	protected = append(protected, agentControlRoots(a.home)...)
	for _, root := range protected {
		if pathWithin(normalized, root) || pathWithin(resolved, resolvePathSymlinks(root)) {
			return true
		}
	}
	base := filepath.Base(normalized)
	return isSecretBasename(base)
}

func (a *analyzer) sensitiveReadPath(path string) bool {
	normalized := a.normalizePath(path)
	resolved := resolvePathSymlinks(normalized)
	base := filepath.Base(normalized)
	if isSecretBasename(base) || isSecretBasename(filepath.Base(resolved)) {
		return true
	}
	privateRoots := []string{
		filepath.Join(a.home, ".gnupg", "private-keys-v1.d"),
		filepath.Join(a.home, ".aws", "credentials"),
		filepath.Join(a.home, ".azure", "accessTokens.json"),
	}
	for _, root := range privateRoots {
		if pathWithin(normalized, root) || pathWithin(resolved, resolvePathSymlinks(root)) {
			return true
		}
	}
	return false
}

func pathWithin(path, root string) bool {
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
		root = strings.ToLower(root)
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return path == root || strings.HasPrefix(path, prefix)
}

// resolvePathSymlinks resolves the longest existing prefix so that a missing
// write target below a symlinked directory is still compared by its real path.
func resolvePathSymlinks(path string) string {
	path = filepath.Clean(path)
	current := path
	suffix := make([]string, 0)
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			parts := append([]string{resolved}, suffix...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return path
		}
		suffix = append([]string{filepath.Base(current)}, suffix...)
		current = parent
	}
}

func (a *analyzer) dangerousDeleteTarget(target string) bool {
	target = filepath.Clean(target)
	if filesystemRoot(target) || a.home != "" && samePath(target, a.home) || a.protectedPath(target) {
		return true
	}
	system := []string{"/System", "/Library", "/Applications", "/Users", "/Volumes", "/private", "/etc", "/usr", "/bin", "/sbin", "/var", "/opt", "/dev"}
	if runtime.GOOS == "windows" {
		system = nil
		for _, path := range []string{
			os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"),
			os.Getenv("ProgramData"),
		} {
			if path != "" {
				system = append(system, filepath.Clean(path))
			}
		}
		if a.home != "" {
			system = append(system, filepath.Dir(a.home))
		}
	}
	for _, path := range system {
		if (runtime.GOOS == "windows" && pathWithin(target, path)) || samePath(target, path) {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	return pathWithin(left, right) && pathWithin(right, left)
}

func (a *analyzer) dangerousGlobTarget(target string) bool {
	index := strings.IndexAny(target, "*?[")
	if index < 0 {
		return false
	}
	prefix := strings.TrimRight(target[:index], `/\`)
	volume := filepath.VolumeName(target)
	if prefix == "" {
		prefix = string(filepath.Separator)
	} else if volume != "" && strings.EqualFold(prefix, volume) {
		prefix = volume + string(filepath.Separator)
	}
	return a.dangerousDeleteTarget(prefix)
}

func filesystemRoot(path string) bool {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(path, root)
	}
	return path == root
}

func stripGitGlobals(args []string, known []bool, cwd string) ([]string, []bool, string, bool) {
	cwdKnown := true
	for len(args) > 0 {
		if args[0] == "-C" {
			if len(args) < 2 {
				return nil, nil, cwd, false
			}
			if len(known) < 2 || !known[1] {
				cwdKnown = false
			} else if cwdKnown {
				cwd = resolveGitCWD(cwd, args[1])
			}
			args, known = args[2:], known[2:]
			continue
		}
		if strings.HasPrefix(args[0], "-C") && len(args[0]) > 2 {
			if len(known) == 0 || !known[0] {
				cwdKnown = false
			} else if cwdKnown {
				cwd = resolveGitCWD(cwd, strings.TrimPrefix(args[0], "-C"))
			}
			args, known = args[1:], known[1:]
			continue
		}
		if args[0] == "-c" || args[0] == "--git-dir" || args[0] == "--work-tree" {
			if len(args) < 2 {
				return nil, nil, cwd, cwdKnown
			}
			args, known = args[2:], known[2:]
			continue
		}
		if strings.HasPrefix(args[0], "-") {
			args, known = args[1:], known[1:]
			continue
		}
		break
	}
	return args, known, cwd, cwdKnown
}

func resolveGitCWD(cwd, path string) string {
	if path == "" {
		return cwd
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(cwd, path))
}

func currentBranch(cwd string) string {
	command := gitCommand(cwd, "branch", "--show-current")
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func emptyGitHistory(cwd string) bool {
	repository := gitCommand(cwd, "rev-parse", "--is-inside-work-tree")
	output, err := repository.Output()
	if err != nil || strings.TrimSpace(string(output)) != "true" {
		return false
	}
	head := gitCommand(cwd, "rev-parse", "--verify", "HEAD")
	return head.Run() != nil
}

func defaultBranch(cwd string) string {
	command := gitCommand(cwd, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(string(output)), "origin/")
}

func isShell(command string) bool { return command == "bash" || command == "sh" || command == "zsh" }

func shellCodeIndex(args []string) int {
	for i, arg := range args {
		if arg == "-c" && i+1 < len(args) {
			return i + 1
		}
	}
	return -1
}

func firstSubcommand(args []string) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return ""
}

func containsAny(args []string, values ...string) bool {
	for _, arg := range args {
		for _, value := range values {
			if arg == value {
				return true
			}
		}
	}
	return false
}

func anyArgPrefix(args []string, prefix string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

func hasForceFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--force" || (strings.HasPrefix(arg, "-") && strings.Contains(strings.TrimPrefix(arg, "-"), "f")) {
			return true
		}
	}
	return false
}

func hasUnsafeForce(args []string) bool {
	if containsAny(args, "--force-with-lease") {
		return false
	}
	return hasForceFlag(args)
}

func curlUploadsFile(args []string) bool {
	for i, arg := range args {
		if (arg == "-d" || arg == "--data" || arg == "-F" || arg == "--form" || arg == "--data-binary" || arg == "--json" || arg == "-T" || arg == "--upload-file") && i+1 < len(args) {
			value := args[i+1]
			if arg == "-T" || arg == "--upload-file" || strings.HasPrefix(value, "@") || strings.Contains(value, "=@") {
				return true
			}
		}
		if strings.HasPrefix(arg, "--upload-file=") || strings.HasPrefix(arg, "--data-binary=@") || strings.HasPrefix(arg, "--json=@") || strings.HasPrefix(arg, "--form=") && strings.Contains(arg, "=@") {
			return true
		}
	}
	return false
}

func isSigningKey(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".keystore" || ext == ".jks" || ext == ".p12" || ext == ".mobileprovision"
}

func isSecretBasename(base string) bool {
	lower := strings.ToLower(base)
	if lower == ".env" || strings.HasPrefix(lower, ".env.") || lower == ".env.keys" {
		return true
	}
	if lower == "id_rsa" || lower == "id_ed25519" || lower == "id_ecdsa" || lower == "id_dsa" {
		return true
	}
	switch filepath.Ext(lower) {
	case ".pem", ".key", ".p12", ".pfx", ".jks":
		return true
	}
	return false
}

func containsRiskLexeme(source string) bool {
	pattern := regexp.MustCompile(`(?i)(\brm\b|\bsudo\b|reset\s+--hard|push\s+--force|\bsecurity\b|\bosascript\b|\btruncate\b|\bshred\b|\bmkfs\b|\bdd\b|\bnc\b|\bnetcat\b|publish|\.ssh|\.env|\.codex|\.claude/hooks)`)
	return pattern.MatchString(source)
}

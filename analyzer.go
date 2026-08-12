package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	cwd               string
	home              string
	language          string
	protectedBranches []string
	findings          []Finding
}

func Analyze(command, cwd string) Result {
	return AnalyzeWithConfig(command, cwd, Config{})
}

func AnalyzeWithConfig(command, cwd string, config Config) Result {
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
	a := &analyzer{cwd: cwd, home: os.Getenv("HOME"), language: config.Output.Language, protectedBranches: config.Git.ProtectedBranches}
	a.analyzeSource(command, 0)
	return a.result()
}

func (a *analyzer) analyzeSource(source string, depth int) {
	if depth > 4 {
		a.add(Review, "nested-shell-depth", "ネストしたshellコードが深すぎるため確認が必要です。", "shell", "")
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "hook")
	if err != nil {
		if containsRiskLexeme(source) {
			a.add(Review, "shell-parse-risk", "危険語を含むshell構文を安全に解析できませんでした。", "shell", "")
		}
		return
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			a.inspectCall(node, depth)
		case *syntax.Redirect:
			a.inspectRedirect(node)
		case *syntax.BinaryCmd:
			if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
				a.inspectPipeline(node)
			}
		}
		return true
	})
}

func (a *analyzer) inspectCall(call *syntax.CallExpr, depth int) {
	if len(call.Args) == 0 {
		return
	}
	words := make([]wordValue, 0, len(call.Args))
	for _, arg := range call.Args {
		words = append(words, evalWord(arg, a.home))
	}
	if !words[0].Known {
		a.add(Review, "dynamic-command-name", "実行するcommand名が動的です。", "dynamic", "")
		return
	}
	argv := make([]string, len(words))
	known := make([]bool, len(words))
	for i, word := range words {
		argv[i], known[i] = word.Value, word.Known
	}
	argv, known = unwrapCommand(argv, known)
	if len(argv) == 0 {
		return
	}
	command := filepath.Base(argv[0])
	args := argv[1:]
	argKnown := known[1:]

	if isShell(command) {
		if index := shellCodeIndex(args); index >= 0 {
			if index < len(argKnown) && argKnown[index] {
				a.analyzeSource(args[index], depth+1)
			} else {
				a.add(Review, "dynamic-shell-code", "動的なshellコードの実行です。", command, "")
			}
		}
	}
	if inlineInterpreterCode(command, args) {
		a.add(Review, "inline-interpreter-code", "Inline interpreter code requires review.", command, "")
	}
	if command == "xargs" && containsExecutionGateway(args) {
		a.add(Review, "indirect-execution-gateway", "Indirect command execution through xargs requires review.", command, "")
	}
	if command == "find" && findExecutesGateway(args) {
		a.add(Review, "indirect-execution-gateway", "Indirect command execution through find requires review.", command, "")
	}
	if command == "find" && containsAny(args, "-delete") {
		a.add(Review, "find-delete", "Deleting files through find requires review.", command, "")
	}

	switch command {
	case "rm":
		a.inspectRM(args, argKnown)
	case "unlink":
		for i, arg := range args {
			if i < len(argKnown) && argKnown[i] && a.protectedPath(arg) {
				a.add(Block, "protected-delete", "agent設定または機密パスの削除をブロックしました。", command, a.normalizePath(arg))
			}
		}
	case "git":
		a.inspectGit(args, argKnown)
	case "sudo":
		a.add(Block, "privilege-escalation", "sudoによる権限昇格をブロックしました。", command, "")
	case "osascript", "security", "screencapture", "mkfs", "csrutil", "nvram", "dscl", "networksetup":
		a.add(Block, "sensitive-system-command", fmt.Sprintf("%sは安全ガードによりブロックされました。", command), command, "")
	case "shutdown", "reboot", "halt", "poweroff":
		a.add(Block, "system-shutdown", "システム停止操作をブロックしました。", command, "")
	case "dd":
		if anyArgPrefix(args, "of=") {
			a.add(Block, "raw-write", "ddによる直接書き込みをブロックしました。", command, "")
		}
	case "truncate", "shred":
		a.add(Block, "destructive-file-command", fmt.Sprintf("%sによる破壊的操作をブロックしました。", command), command, "")
	case "nc", "ncat", "netcat":
		a.add(Block, "raw-network-channel", "nc/netcatによる直接通信をブロックしました。", command, "")
	case "curl":
		if curlUploadsFile(args) {
			a.add(Block, "file-upload", "curlによるファイル送信をブロックしました。", command, "")
		}
	case "wget":
		if containsAny(args, "--post-data", "--post-file", "--body-file") || anyArgPrefix(args, "--post-file=") || anyArgPrefix(args, "--body-file=") {
			a.add(Block, "file-upload", "wgetによるデータ送信をブロックしました。", command, "")
		}
	case "scp", "sftp":
		if command == "sftp" || anyRemotePath(args) {
			a.add(Review, "remote-file-transfer", "Remote file transfer requires review.", command, "")
		}
	case "rsync":
		if anyRemotePath(args) {
			a.add(Review, "remote-file-transfer", "Remote file transfer requires review.", command, "")
		}
	case "rclone":
		if transferSubcommand(args) && anyRemotePath(args) {
			a.add(Review, "remote-file-transfer", "Remote file transfer requires review.", command, "")
		}
	case "aws":
		if cloudStorageTransfer(args, "s3") {
			a.add(Review, "cloud-storage-transfer", "Cloud storage transfer requires review.", command, "")
		}
	case "gsutil":
		if containsAny(args, "cp", "mv", "rsync") {
			a.add(Review, "cloud-storage-transfer", "Cloud storage transfer requires review.", command, "")
		}
	case "az":
		if len(args) >= 3 && args[0] == "storage" && (args[1] == "blob" || args[1] == "file") && containsAny(args[2:], "upload", "upload-batch", "sync") {
			a.add(Review, "cloud-storage-transfer", "Cloud storage transfer requires review.", command, "")
		}
	case "tar", "zip", "7z", "7zz", "ditto", "cpio":
		if archiveContainsProtectedPath(args, argKnown, a) {
			a.add(Review, "sensitive-archive", "Archiving an agent configuration or sensitive path requires review.", command, "")
		}
	case "docker", "podman":
		if containerPrune(args) {
			a.add(Review, "container-prune", "Container cleanup may delete images, volumes, or build data.", command, "")
		}
	case "kubectl":
		if firstSubcommand(args) == "delete" {
			a.add(Review, "infrastructure-delete", "Infrastructure resource deletion requires review.", command, "")
		}
	case "terraform", "tofu":
		if firstSubcommand(args) == "destroy" || containsAny(args, "-destroy") {
			a.add(Review, "infrastructure-delete", "Infrastructure resource deletion requires review.", command, "")
		}
	case "helm":
		if sub := firstSubcommand(args); sub == "uninstall" || sub == "delete" {
			a.add(Review, "infrastructure-delete", "Infrastructure resource deletion requires review.", command, "")
		}
	case "eval", "source", ".":
		a.add(Review, "dynamic-code-gateway", fmt.Sprintf("%sによる動的コード実行です。", command), command, "")
	case "brew":
		if firstSubcommand(args) == "uninstall" || firstSubcommand(args) == "remove" || firstSubcommand(args) == "untap" {
			a.add(Review, "package-removal", "Homebrewパッケージの削除です。", command, "")
		}
	case "npm", "pnpm":
		if firstSubcommand(args) == "publish" {
			a.add(Block, "package-publish", "パッケージ公開をブロックしました。", command, "")
		}
	case "chmod":
		if containsAny(args, "777") {
			a.add(Block, "world-writable", "chmod 777をブロックしました。", command, "")
		}
		for i, arg := range args {
			if i < len(argKnown) && argKnown[i] && a.protectedPath(arg) {
				a.add(Block, "guard-self-protection", "agent設定または機密パスの権限変更をブロックしました。", command, a.normalizePath(arg))
			}
		}
	case "chown":
		for i, arg := range args {
			if i < len(argKnown) && argKnown[i] && a.protectedPath(arg) {
				a.add(Block, "guard-self-protection", "agent設定または機密パスの所有者変更をブロックしました。", command, a.normalizePath(arg))
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
			a.add(Review, "dynamic-protected-symlink", "symbolic linkの参照先を特定できません。", "ln", "dynamic")
			return
		}
		if a.protectedPath(arg) {
			a.add(Block, "protected-symlink", "保護対象を指すsymbolic linkの作成をブロックしました。", "ln", a.normalizePath(arg))
		}
		return
	}
}

func (a *analyzer) inspectSensitiveReadArgs(command string, args []string, known []bool) {
	for i, arg := range args {
		if i < len(known) && known[i] && a.sensitiveReadPath(arg) {
			a.add(Block, "sensitive-shell-read", "shell経由の機密ファイル読み取りをブロックしました。", command, a.normalizePath(arg))
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
			a.add(Block, "guard-self-protection", "agent設定または機密パスへの書き込みをブロックしました。", command, a.normalizePath(args[i]))
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
					a.add(Block, "protected-delete", "agent設定または機密パスの削除をブロックしました。", "rm", a.normalizePath(args[index]))
				} else if isSigningKey(args[index]) {
					a.add(Review, "signing-key-delete", "署名鍵または証明書の削除です。", "rm", a.normalizePath(args[index]))
				}
			}
		}
		return
	}
	for _, index := range targets {
		if index >= len(known) || !known[index] {
			a.add(Review, "dynamic-recursive-delete", "再帰削除の対象パスを静的に確定できません。", "rm", "dynamic")
			continue
		}
		target := a.normalizePath(args[index])
		if a.dangerousDeleteTarget(target) {
			a.add(Block, "recursive-delete-protected", "保護対象への再帰削除をブロックしました。", "rm", target)
		}
	}
}

func (a *analyzer) inspectPipeline(pipeline *syntax.BinaryCmd) {
	leftSource := statementHasSensitiveSource(pipeline.X, a)
	rightSink := statementHasNetworkOrShellSink(pipeline.Y)
	if leftSource && rightSink {
		a.add(Block, "sensitive-pipeline", "機密データを外部送信またはshell実行するpipelineをブロックしました。", "pipeline", "")
	}
	if statementHasNetworkSource(pipeline.X) && statementHasShellSink(pipeline.Y) {
		a.add(Block, "download-to-shell", "networkから取得したデータの直接shell実行をブロックしました。", "pipeline", "")
	}
	if statementHasDecoderSource(pipeline.X) && statementHasShellSink(pipeline.Y) {
		a.add(Block, "decoded-to-shell", "Decoded content piped directly into a shell was blocked.", "pipeline", "")
	}
}

func statementHasSensitiveSource(stmt *syntax.Stmt, a *analyzer) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := literalWords(call.Args, a.home)
		if len(words) == 0 {
			return true
		}
		command := filepath.Base(words[0].Value)
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
		words := literalWords(call.Args, os.Getenv("HOME"))
		if len(words) == 0 || !words[0].Known {
			return true
		}
		command := filepath.Base(words[0].Value)
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

func inlineInterpreterCode(command string, args []string) bool {
	flags := []string(nil)
	switch {
	case regexp.MustCompile(`^python[0-9.]*$`).MatchString(command):
		flags = []string{"-c"}
	case command == "node":
		flags = []string{"-e", "--eval", "-p", "--print"}
	case command == "ruby":
		flags = []string{"-e"}
	case command == "perl":
		flags = []string{"-e", "-E"}
	case command == "php":
		flags = []string{"-r"}
	case command == "lua" || strings.HasPrefix(command, "lua5."):
		flags = []string{"-e"}
	case command == "deno" && firstSubcommand(args) == "eval":
		return true
	case command == "bun":
		flags = []string{"-e", "--eval", "-p", "--print"}
	}
	return containsAny(args, flags...)
}

func containsExecutionGateway(args []string) bool {
	for _, arg := range args {
		command := filepath.Base(arg)
		if isShell(command) || inlineInterpreterName(command) {
			return true
		}
	}
	return false
}

func findExecutesGateway(args []string) bool {
	for i, arg := range args {
		if (arg == "-exec" || arg == "-execdir" || arg == "-ok" || arg == "-okdir") && i+1 < len(args) {
			command := filepath.Base(args[i+1])
			return isShell(command) || inlineInterpreterName(command)
		}
	}
	return false
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
		value := evalWord(call.Args[0], os.Getenv("HOME"))
		if value.Known && predicate(filepath.Base(value.Value)) {
			found = true
			return false
		}
		return true
	})
	return found
}

func literalWords(words []*syntax.Word, home string) []wordValue {
	result := make([]wordValue, 0, len(words))
	for _, word := range words {
		result = append(result, evalWord(word, home))
	}
	return result
}

func (a *analyzer) inspectGit(args []string, known []bool) {
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
			a.add(Review, "git-dynamic-working-directory", "The Git working directory cannot be determined.", "git", "dynamic")
			return
		}
		a.inspectGitBranch(rest, restKnown, gitCWD)
	case "reset":
		if containsAny(rest, "--hard") {
			a.add(Block, "git-reset-hard", "git reset --hardをブロックしました。", "git", "")
		}
	case "clean":
		if hasForceFlag(rest) {
			a.add(Review, "git-clean-force", "git cleanによる未追跡ファイル削除です。", "git", "")
		}
	case "stash":
		if len(rest) > 0 && (rest[0] == "drop" || rest[0] == "clear") {
			a.add(Review, "git-stash-delete", "git stashの削除です。", "git", "")
		}
	case "push":
		if !cwdKnown {
			a.add(Review, "git-dynamic-working-directory", "The Git working directory cannot be determined.", "git", "dynamic")
			return
		}
		a.inspectGitPush(rest, restKnown, gitCWD)
	case "commit":
		if !cwdKnown {
			a.add(Review, "git-dynamic-working-directory", "The Git working directory cannot be determined.", "git", "dynamic")
			return
		}
		if branch := currentBranch(gitCWD); a.protectedBranch(branch, gitCWD) {
			a.add(Block, "protected-branch-direct-commit", "保護ブランチへの直接commitをブロックしました。", "git", branch)
		}
	}
}

func (a *analyzer) inspectGitBranch(args []string, known []bool, gitCWD string) {
	deleting := containsAny(args, "-d", "-D", "--delete")
	if !deleting {
		return
	}
	if !allKnown(known) {
		a.add(Review, "git-dynamic-branch-delete", "削除するローカルブランチを特定できません。", "git", "dynamic")
		return
	}
	for _, branch := range gitOperands(args) {
		if a.protectedBranch(branch, gitCWD) {
			a.add(Block, "protected-branch-delete", "保護ブランチの削除をブロックしました。", "git", branch)
		}
	}
}

func (a *analyzer) inspectGitPush(args []string, known []bool, gitCWD string) {
	if !allKnown(known) {
		a.add(Review, "git-dynamic-push-ref", "push対象のrefを特定できません。", "git", "dynamic")
		return
	}
	parsed := parseGitPushArgs(args)
	if parsed.bulk {
		a.add(Block, "protected-branch-bulk-push", "保護ブランチを含み得る一括pushをブロックしました。", "git", "all")
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
			a.add(Review, "git-remote-delete-unknown", "削除するremote refを特定できません。", "git", "dynamic")
			return
		}
		for _, target := range targets {
			target = strings.TrimPrefix(target, ":")
			if target == "tag" || strings.HasPrefix(target, "refs/tags/") {
				a.add(Review, "git-remote-tag-delete", "remote tagの削除です。", "git", target)
			} else if a.protectedBranch(strings.TrimPrefix(target, "refs/heads/"), gitCWD) {
				a.add(Block, "protected-remote-branch-delete", "保護remoteブランチの削除をブロックしました。", "git", target)
			}
		}
		return
	}

	if len(targets) == 0 {
		targets = []string{currentBranch(gitCWD)}
	}
	for _, target := range targets {
		target = pushedBranch(target, currentBranch(gitCWD))
		if target != "" && a.protectedBranch(target, gitCWD) {
			a.add(Block, "protected-branch-push", "保護ブランチへのpushをブロックしました。", "git", target)
			return
		}
	}
	if hasUnsafeForce(args) || hasForcedRefspec(parsed.refspecs) {
		a.add(Review, "git-force-push", "git push --forceです。--force-with-leaseを検討してください。", "git", "")
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
	refspecs []string
	bulk     bool
}

func parseGitPushArgs(args []string) gitPushArgs {
	operands := make([]string, 0, len(args))
	repositoryOption := false
	endOptions := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !endOptions && arg == "--" {
			endOptions = true
			continue
		}
		if !endOptions {
			if arg == "--all" || arg == "--mirror" {
				return gitPushArgs{bulk: true}
			}
			if arg == "--repo" {
				repositoryOption = true
				if i+1 < len(args) {
					i++
				}
				continue
			}
			if strings.HasPrefix(arg, "--repo=") {
				repositoryOption = true
				continue
			}
			if pushOptionTakesValue(arg) {
				if i+1 < len(args) {
					i++
				}
				continue
			}
			if strings.HasPrefix(arg, "-") {
				continue
			}
		}
		operands = append(operands, arg)
	}
	if repositoryOption {
		return gitPushArgs{refspecs: operands}
	}
	if len(operands) < 2 {
		return gitPushArgs{}
	}
	return gitPushArgs{refspecs: operands[1:]}
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
		word := evalWord(redir.Word, a.home)
		if word.Known && a.sensitiveReadPath(word.Value) {
			a.add(Block, "sensitive-input-redirection", "redirectionによる機密ファイル読み取りをブロックしました。", "redirect", a.normalizePath(word.Value))
		}
		return
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
	default:
		return
	}
	word := evalWord(redir.Word, a.home)
	if word.Known && a.protectedPath(word.Value) {
		a.add(Block, "protected-redirection", "agent設定または機密パスへのredirectionをブロックしました。", "redirect", a.normalizePath(word.Value))
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
	}
	return Result{Decision: decision, Message: message, Findings: a.findings}
}

func (a *analyzer) add(decision Decision, ruleID, message, command, target string) {
	finding := Finding{Decision: decision, RuleID: ruleID, Message: message, Command: command, Target: target}
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

func evalWord(word *syntax.Word, home string) wordValue {
	var builder strings.Builder
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
					if nested.Param != nil && nested.Param.Value == "HOME" && !nested.Excl && nested.Exp == nil {
						builder.WriteString(home)
					} else {
						return wordValue{Known: false}
					}
				default:
					return wordValue{Known: false}
				}
			}
		case *syntax.ParamExp:
			if part.Param != nil && part.Param.Value == "HOME" && !part.Excl && part.Exp == nil {
				builder.WriteString(home)
			} else {
				return wordValue{Known: false}
			}
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
		switch filepath.Base(argv[0]) {
		case "command", "nohup", "time":
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
	} else if strings.HasPrefix(path, "~/") {
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
		filepath.Join(a.home, ".gcloud"), filepath.Join(a.home, ".claude", "hooks"),
		filepath.Join(a.home, ".claude", "settings.json"), filepath.Join(a.home, ".codex", "hooks"),
		filepath.Join(a.home, ".codex", "hooks.json"), filepath.Join(a.home, ".codex", "config.toml"),
		filepath.Join(a.home, ".agents"), filepath.Join(a.home, ".local", "bin", "agent-command-guard"),
	}
	if configPath, err := DefaultConfigPath(); err == nil {
		protected = append(protected, configPath)
	}
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
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
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
	if target == string(filepath.Separator) || target == a.home || a.protectedPath(target) {
		return true
	}
	system := []string{"/System", "/Library", "/Applications", "/Users", "/Volumes", "/private", "/etc", "/usr", "/bin", "/sbin", "/var", "/opt", "/dev"}
	for _, path := range system {
		if target == path {
			return true
		}
	}
	return false
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
	command := exec.Command("/usr/bin/git", "-C", cwd, "branch", "--show-current")
	command.Env = []string{"PATH=/usr/bin:/bin"}
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func defaultBranch(cwd string) string {
	command := exec.Command("/usr/bin/git", "-C", cwd, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
	command.Env = []string{"PATH=/usr/bin:/bin"}
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

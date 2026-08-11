package main

import (
	"fmt"
	"strings"
)

type translations struct {
	en string
	ja string
}

var findingMessages = map[string]translations{
	"nested-shell-depth":             {"Nested shell code is too deep and requires review.", "ネストしたshellコードが深すぎるため確認が必要です。"},
	"shell-parse-risk":               {"Shell syntax containing risky terms could not be parsed safely.", "危険語を含むshell構文を安全に解析できませんでした。"},
	"dynamic-command-name":           {"The command name is dynamic.", "実行するcommand名が動的です。"},
	"dynamic-shell-code":             {"Dynamic shell code is being executed.", "動的なshellコードの実行です。"},
	"protected-delete":               {"Deletion of an agent configuration or sensitive path was blocked.", "agent設定または機密パスの削除をブロックしました。"},
	"privilege-escalation":           {"Privilege escalation with sudo was blocked.", "sudoによる権限昇格をブロックしました。"},
	"sensitive-system-command":       {"The {command} command was blocked by the safety guard.", "{command}は安全ガードによりブロックされました。"},
	"system-shutdown":                {"A system shutdown operation was blocked.", "システム停止操作をブロックしました。"},
	"raw-write":                      {"A direct write with dd was blocked.", "ddによる直接書き込みをブロックしました。"},
	"destructive-file-command":       {"A destructive operation with {command} was blocked.", "{command}による破壊的操作をブロックしました。"},
	"raw-network-channel":            {"Direct communication with nc/netcat was blocked.", "nc/netcatによる直接通信をブロックしました。"},
	"file-upload":                    {"A file upload with {command} was blocked.", "{command}によるファイル送信をブロックしました。"},
	"dynamic-code-gateway":           {"Dynamic code execution through {command} requires review.", "{command}による動的コード実行です。"},
	"package-removal":                {"A Homebrew package removal requires review.", "Homebrewパッケージの削除です。"},
	"package-publish":                {"Package publication was blocked.", "パッケージ公開をブロックしました。"},
	"world-writable":                 {"chmod 777 was blocked.", "chmod 777をブロックしました。"},
	"guard-self-protection":          {"Writing to or changing an agent configuration or sensitive path was blocked.", "agent設定または機密パスへの変更をブロックしました。"},
	"dynamic-protected-symlink":      {"The symbolic link target cannot be determined.", "symbolic linkの参照先を特定できません。"},
	"protected-symlink":              {"Creation of a symbolic link to a protected path was blocked.", "保護対象を指すsymbolic linkの作成をブロックしました。"},
	"sensitive-shell-read":           {"Reading a sensitive file through the shell was blocked.", "shell経由の機密ファイル読み取りをブロックしました。"},
	"dynamic-recursive-delete":       {"The recursive deletion target cannot be determined statically.", "再帰削除の対象パスを静的に確定できません。"},
	"signing-key-delete":             {"Deletion of a signing key or certificate requires review.", "署名鍵または証明書の削除です。"},
	"recursive-delete-protected":     {"Recursive deletion of a protected target was blocked.", "保護対象への再帰削除をブロックしました。"},
	"sensitive-pipeline":             {"A pipeline sending sensitive data externally or into a shell was blocked.", "機密データを外部送信またはshell実行するpipelineをブロックしました。"},
	"download-to-shell":              {"Piping network content directly into a shell was blocked.", "networkから取得したデータの直接shell実行をブロックしました。"},
	"protected-branch-delete":        {"Deletion of a protected branch was blocked.", "保護ブランチの削除をブロックしました。"},
	"git-dynamic-branch-delete":      {"The local branch to delete cannot be determined.", "削除するローカルブランチを特定できません。"},
	"git-reset-hard":                 {"git reset --hard was blocked.", "git reset --hardをブロックしました。"},
	"git-clean-force":                {"git clean will delete untracked files.", "git cleanによる未追跡ファイル削除です。"},
	"git-stash-delete":               {"Deletion of a git stash requires review.", "git stashの削除です。"},
	"git-dynamic-push-ref":           {"The ref being pushed cannot be determined.", "push対象のrefを特定できません。"},
	"protected-branch-bulk-push":     {"A bulk push that may include protected branches was blocked.", "保護ブランチを含み得る一括pushをブロックしました。"},
	"git-remote-delete-unknown":      {"The remote ref to delete cannot be determined.", "削除するremote refを特定できません。"},
	"git-remote-tag-delete":          {"Deletion of a remote tag requires review.", "remote tagの削除です。"},
	"protected-remote-branch-delete": {"Deletion of a protected remote branch was blocked.", "保護remoteブランチの削除をブロックしました。"},
	"protected-branch-push":          {"A push to a protected branch was blocked.", "保護ブランチへのpushをブロックしました。"},
	"git-force-push":                 {"This is a force push. Consider using --force-with-lease.", "git push --forceです。--force-with-leaseを検討してください。"},
	"protected-branch-direct-commit": {"A direct commit to a protected branch was blocked.", "保護ブランチへの直接commitをブロックしました。"},
	"sensitive-input-redirection":    {"Reading a sensitive file through input redirection was blocked.", "redirectionによる機密ファイル読み取りをブロックしました。"},
	"protected-redirection":          {"Redirection to an agent configuration or sensitive path was blocked.", "agent設定または機密パスへのredirectionをブロックしました。"},
	"inline-interpreter-code":        {"Inline code execution with {command} requires review.", "{command}によるインラインコード実行は確認が必要です。"},
	"indirect-execution-gateway":     {"Indirect command execution through {command} requires review.", "{command}を介した間接的なコマンド実行は確認が必要です。"},
	"decoded-to-shell":               {"Decoded content piped directly into a shell was blocked.", "復号・展開した内容のshellへの直接実行をブロックしました。"},
	"remote-file-transfer":           {"Remote file transfer with {command} requires review.", "{command}によるremoteファイル転送は確認が必要です。"},
	"cloud-storage-transfer":         {"Cloud storage transfer with {command} requires review.", "{command}によるcloud storage転送は確認が必要です。"},
	"find-delete":                    {"Deleting files through find requires review.", "findによるファイル削除は確認が必要です。"},
	"sensitive-archive":              {"Archiving an agent configuration or sensitive path requires review.", "agent設定または機密パスのアーカイブ作成は確認が必要です。"},
	"container-prune":                {"Container cleanup may delete images, volumes, or build data.", "コンテナのクリーンアップによりimage、volume、build dataが削除される可能性があります。"},
	"infrastructure-delete":          {"Infrastructure resource deletion requires review.", "インフラリソースの削除は確認が必要です。"},
}

func findingMessage(language string, finding Finding) string {
	message, ok := findingMessages[finding.RuleID]
	if !ok {
		return finding.Message
	}
	text := message.en
	if language == "ja" {
		text = message.ja
	}
	return strings.ReplaceAll(text, "{command}", finding.Command)
}

func customRuleMessage(language, ruleID string) string {
	if language == "ja" {
		return fmt.Sprintf("カスタムルール %q が一致しました。", ruleID)
	}
	return fmt.Sprintf("Custom rule %q matched.", ruleID)
}

func targetMessage(language, target string) string {
	if language == "ja" {
		return " 対象: " + target
	}
	return " Target: " + target
}

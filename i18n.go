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
	"shell-parse-risk":               {"Shell syntax could not be parsed safely.", "shell構文を安全に解析できませんでした。"},
	"shell-parser-unavailable":       {"The shell parser is unavailable, so the command requires review.", "shell parserを利用できないためcommandの確認が必要です。"},
	"dynamic-command-name":           {"The command name is dynamic.", "実行するcommand名が動的です。"},
	"dynamic-shell-code":             {"Dynamic shell code is being executed.", "動的なshellコードの実行です。"},
	"protected-delete":               {"Deletion of an agent configuration or sensitive path was blocked.", "agent設定または機密パスの削除をブロックしました。"},
	"privilege-escalation":           {"Privilege escalation with {command} was blocked.", "{command}による権限昇格をブロックしました。"},
	"sensitive-system-command":       {"The {command} command was blocked by the safety guard.", "{command}は安全ガードによりブロックされました。"},
	"system-shutdown":                {"A system shutdown operation was blocked.", "システム停止操作をブロックしました。"},
	"raw-write":                      {"A direct write with dd was blocked.", "ddによる直接書き込みをブロックしました。"},
	"destructive-file-command":       {"A destructive operation with {command} was blocked.", "{command}による破壊的操作をブロックしました。"},
	"raw-network-channel":            {"Direct communication with nc/netcat was blocked.", "nc/netcatによる直接通信をブロックしました。"},
	"file-upload":                    {"A file upload with {command} was blocked.", "{command}によるファイル送信をブロックしました。"},
	"dynamic-code-gateway":           {"Dynamic code execution through {command} requires review.", "{command}による動的コード実行です。"},
	"package-removal":                {"A Homebrew package removal requires review.", "Homebrewパッケージの削除です。"},
	"package-publish":                {"Package publication was blocked.", "パッケージ公開をブロックしました。"},
	"artifact-publish":               {"Pushing a build artifact with {command} requires review.", "{command}によるビルド成果物のpushは確認が必要です。"},
	"repository-administration":      {"A destructive repository operation with {command} was blocked.", "{command}によるリポジトリの破壊的操作をブロックしました。"},
	"dns-exfiltration":               {"A DNS lookup built from command output was blocked.", "コマンド出力から組み立てたDNS問い合わせをブロックしました。"},
	"browser-navigation":             {"Opening a URL in the browser requires review.", "ブラウザでのURL表示は確認が必要です。"},
	"container-host-mount":           {"Mounting the host filesystem into a container requires review.", "ホストファイルシステムのコンテナへのマウントは確認が必要です。"},
	"path-override":                  {"Replacing PATH outright requires review.", "PATHの全置換は確認が必要です。"},
	"environment-override":           {"Reassigning a core environment variable requires review.", "重要な環境変数の変更は確認が必要です。"},
	"proxy-override":                 {"Setting a proxy variable requires review.", "プロキシ環境変数の設定は確認が必要です。"},
	"world-writable":                 {"A chmod granting world write access was blocked.", "全ユーザーに書き込みを許可するchmodをブロックしました。"},
	"destructive-storage-command":    {"A destructive storage operation with {command} was blocked.", "{command}による破壊的なストレージ操作をブロックしました。"},
	"device-write":                   {"Writing directly to a block device was blocked.", "ブロックデバイスへの直接書き込みをブロックしました。"},
	"fork-bomb":                      {"A fork bomb declaration was blocked.", "fork bombの定義をブロックしました。"},
	"scheduled-job-wipe":             {"Deleting the entire crontab was blocked.", "crontabの全削除をブロックしました。"},
	"managed-state-destroy":          {"Tearing down state managed by {command} was blocked.", "{command}が管理する状態の破棄をブロックしました。"},
	"system-preferences-delete":      {"Deleting a macOS preference domain requires review.", "macOS設定ドメインの削除は確認が必要です。"},
	"launch-service-change":          {"Loading or unloading a launch service requires review.", "launchサービスの登録・解除は確認が必要です。"},
	"guard-self-protection":          {"Writing to or changing an agent configuration or sensitive path was blocked.", "agent設定または機密パスへの変更をブロックしました。"},
	"dynamic-protected-write":        {"The write target cannot be determined statically.", "書き込み対象を静的に確定できません。"},
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
	"protected-branch-exception":     {"A structured protected-branch exception matched.", "構造化された保護ブランチ例外が一致しました。"},
	"git-dynamic-working-directory":  {"The Git working directory cannot be determined.", "Gitの作業ディレクトリを特定できません。"},
	"sensitive-input-redirection":    {"Reading a sensitive file through input redirection was blocked.", "redirectionによる機密ファイル読み取りをブロックしました。"},
	"protected-redirection":          {"Redirection to an agent configuration or sensitive path was blocked.", "agent設定または機密パスへのredirectionをブロックしました。"},
	"inline-interpreter-code":        {"Inline code execution with {command} requires review.", "{command}によるインラインコード実行は確認が必要です。"},
	"protected-interpreter-payload":  {"Inline {command} code naming an agent configuration or sensitive path was blocked.", "agent設定または機密パスを指定した{command}のインラインコードをブロックしました。"},
	"indirect-execution-gateway":     {"Indirect command execution through {command} requires review.", "{command}を介した間接的なコマンド実行は確認が必要です。"},
	"decoded-to-shell":               {"Decoded content piped directly into a shell was blocked.", "復号・展開した内容のshellへの直接実行をブロックしました。"},
	"remote-file-transfer":           {"Remote file transfer with {command} requires review.", "{command}によるremoteファイル転送は確認が必要です。"},
	"cloud-storage-transfer":         {"Cloud storage transfer with {command} requires review.", "{command}によるcloud storage転送は確認が必要です。"},
	"find-delete":                    {"Deleting files through find requires review.", "findによるファイル削除は確認が必要です。"},
	"sensitive-archive":              {"Archiving an agent configuration or sensitive path requires review.", "agent設定または機密パスのアーカイブ作成は確認が必要です。"},
	"credential-archive":             {"Archiving a credential store was blocked.", "認証情報ストアのアーカイブ作成をブロックしました。"},
	"sensitive-remote-transfer":      {"Sending a credential to another machine was blocked.", "認証情報の他マシンへの送信をブロックしました。"},
	"container-prune":                {"Container cleanup may delete images, volumes, or build data.", "コンテナのクリーンアップによりimage、volume、build dataが削除される可能性があります。"},
	"infrastructure-delete":          {"Infrastructure resource deletion requires review.", "インフラリソースの削除は確認が必要です。"},
	"invalid-file-path":              {"The file tool path is missing or invalid.", "ファイルツールのパスが未指定または不正です。"},
	"invalid-file-operation":         {"The file operation is unsupported.", "未対応のファイル操作です。"},
	"sensitive-file-read":            {"Reading a private key or credential file was blocked.", "秘密鍵または認証情報ファイルの読み取りをブロックしました。"},
	"sensitive-file-read-review":     {"This file may contain credentials and requires review before reading.", "認証情報を含む可能性があるため、読み取り前に確認が必要です。"},
	"sensitive-file-write":           {"Writing to a credential, persistence, or agent control path was blocked.", "認証情報、永続化、またはagent制御パスへの書き込みをブロックしました。"},
	"shell-profile-write":            {"Writing to a Zsh profile requires review.", "Zshプロファイルへの書き込みは確認が必要です。"},
	"outside-workspace-write":        {"Writing outside the current workspace requires review.", "現在のworkspace外への書き込みは確認が必要です。"},

	"github-pull-request-create":            {"Pull request creation is blocked for this GitHub repository.", "このGitHubリポジトリではpull requestの作成をブロックしています。"},
	"github-pull-request-target-unknown":    {"Pull request creation was blocked because the GitHub repository target could not be determined safely.", "対象のGitHubリポジトリを安全に特定できないため、pull requestの作成をブロックしました。"},
	"github-pull-request-operation-unknown": {"A dynamic or custom GitHub operation was blocked because it could create a pull request.", "pull requestを作成する可能性がある動的またはカスタムのGitHub操作をブロックしました。"},

	"protected-branch-exception-compound-command":    {"The structured protected-branch exception matched, but it does not apply inside a compound command. Run the protected Git operation separately.", "構造化された保護ブランチ例外には一致しましたが、複合コマンド内では適用されません。保護されたGit操作を単独で実行してください。"},
	"protected-branch-exception-pipeline":            {"The structured protected-branch exception matched, but it does not apply inside a pipeline. Run the protected Git operation separately.", "構造化された保護ブランチ例外には一致しましたが、pipeline内では適用されません。保護されたGit操作を単独で実行してください。"},
	"protected-branch-exception-redirection":         {"The structured protected-branch exception matched, but it does not apply to an invocation with redirection. Run the protected Git operation separately.", "構造化された保護ブランチ例外には一致しましたが、redirectionを伴う実行には適用されません。保護されたGit操作を単独で実行してください。"},
	"protected-branch-exception-indirect-invocation": {"The structured protected-branch exception matched, but it does not apply through wrappers, subshells, assignments, or other indirect invocation. Run Git directly as a standalone command.", "構造化された保護ブランチ例外には一致しましたが、wrapper、subshell、環境変数代入などを介した間接実行には適用されません。Gitを直接かつ単独で実行してください。"},
	"protected-branch-exception-requires-standalone": {"The structured protected-branch exception matched, but it does not apply to this invocation shape. Run the protected Git operation directly as a standalone command.", "構造化された保護ブランチ例外には一致しましたが、この実行形式には適用されません。保護されたGit操作を直接かつ単独で実行してください。"},
}

func findingMessage(language string, finding Finding) string {
	message, ok := findingMessages[finding.RuleID]
	if !ok {
		if language == "ja" {
			return fmt.Sprintf("安全ルール %q が一致しました。", finding.RuleID)
		}
		return fmt.Sprintf("Safety rule %q matched.", finding.RuleID)
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

// The rule identifier is what makes a decision findable — in the corpus, in the
// source, and in a report. Without it the reader has only prose describing the
// outcome, and has to search the policy to learn which rule produced it.
func ruleReference(language, ruleID string) string {
	if ruleID == "" {
		return ""
	}
	if language == "ja" {
		return " [ルール: " + ruleID + "]"
	}
	return " [rule: " + ruleID + "]"
}

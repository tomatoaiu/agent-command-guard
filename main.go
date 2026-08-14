package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type hookInput struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	CWD       string         `json:"cwd"`
}

func main() {
	agent := flag.String("agent", "codex", "hook protocol: codex or claude")
	permissionRequest := flag.Bool("permission-request", false, "approve only structurally safe Codex permission requests")
	explain := flag.Bool("explain", false, "emit the normalized decision for testing")
	configPath := flag.String("config", "", "TOML policy path (default: user config directory)")
	shellName := flag.String("shell", "auto", "shell syntax: auto, posix, or powershell")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionText())
		return
	}
	shell, err := parseShellDialect(*shellName)
	if err != nil {
		fatal(err)
	}
	config, err := LoadConfig(*configPath, *configPath != "")
	if err != nil {
		fatal(err)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	var input hookInput
	if err := json.Unmarshal(data, &input); err != nil {
		fatal(fmt.Errorf("invalid hook input: %w", err))
	}
	command := stringField(input.ToolInput, "command", "cmd")
	if *permissionRequest {
		if shell.resolved() != ShellPOSIX {
			return
		}
		if SafeTempCleanup(command, input.CWD) {
			_ = json.NewEncoder(os.Stdout).Encode(permissionRequestAllow())
		}
		return
	}
	decision := analyzeHookInput(input, config, shell)
	if *explain {
		_ = json.NewEncoder(os.Stdout).Encode(decision)
		return
	}
	if decision.Decision == Allow {
		return
	}
	emitHookDecision(*agent, decision)
}

func analyzeHookInput(input hookInput, config Config, shell ShellDialect) Result {
	if operation, ok := fileOperationForTool(input.ToolName); ok {
		path := stringField(input.ToolInput, "file_path", "path", "notebook_path")
		return AnalyzeFile(operation, path, input.CWD, config)
	}
	return AnalyzeWithConfigAndShell(stringField(input.ToolInput, "command", "cmd"), input.CWD, config, shell)
}

func fileOperationForTool(toolName string) (FileOperation, bool) {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "read", "view", "open", "read_file":
		return FileRead, true
	case "edit", "write", "write_file", "apply_patch", "multiedit", "multi_edit", "notebookedit", "notebook_edit":
		return FileWrite, true
	default:
		return "", false
	}
}

func permissionRequestAllow() map[string]any {
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName": "PermissionRequest",
			"decision": map[string]any{
				"behavior": "allow",
			},
		},
	}
}

func stringField(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := input[key].(string); ok {
			return value
		}
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func emitHookDecision(agent string, decision Result) {
	_ = json.NewEncoder(os.Stdout).Encode(hookDecision(agent, decision))
}

func hookDecision(agent string, decision Result) map[string]any {
	permissionDecision := "deny"
	if agent == "claude" && decision.Decision == Review {
		permissionDecision = "ask"
	}
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       permissionDecision,
			"permissionDecisionReason": decision.Message,
		},
	}
}

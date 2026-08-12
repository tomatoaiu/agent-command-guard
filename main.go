package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
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
	flag.Parse()
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
		if SafeTempCleanup(command, input.CWD) {
			_ = json.NewEncoder(os.Stdout).Encode(permissionRequestAllow())
		}
		return
	}
	decision := AnalyzeWithConfig(command, input.CWD, config)
	if *explain {
		_ = json.NewEncoder(os.Stdout).Encode(decision)
		return
	}
	if decision.Decision == Allow {
		return
	}
	emitHookDecision(*agent, decision)
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

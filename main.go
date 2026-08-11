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
	explain := flag.Bool("explain", false, "emit the normalized decision for testing")
	flag.Parse()

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	var input hookInput
	if err := json.Unmarshal(data, &input); err != nil {
		fatal(fmt.Errorf("invalid hook input: %w", err))
	}
	command := stringField(input.ToolInput, "command", "cmd")
	decision := Analyze(command, input.CWD)
	if *explain {
		_ = json.NewEncoder(os.Stdout).Encode(decision)
		return
	}
	if decision.Decision == Allow {
		return
	}
	emitHookDecision(*agent, decision)
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
	permissionDecision := "deny"
	if agent == "claude" && decision.Decision == Review {
		permissionDecision = "ask"
	}
	out := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       permissionDecision,
			"permissionDecisionReason": decision.Message,
		},
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

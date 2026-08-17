package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Suppression removes one built-in finding when the analyzed command matches
// the configured scope. Unlike an allow rule, it does not bypass the built-in
// policy: the shell input is still parsed and every other finding it produces
// is still reported. This makes it safe for a compound command, where only the
// suppressed part is silenced and the remaining commands keep their decisions.
type Suppression struct {
	RuleID      string   `toml:"rule_id"`
	Commands    []string `toml:"commands"`
	Directories []string `toml:"directories"`

	commandSet map[string]bool
}

// suppressibleRuleIDs limits suppression to built-in findings that are
// context dependent enough to be a false positive inside a trusted workspace.
// Credential, persistence, agent-control, and guard self-protection findings
// are deliberately absent, matching the guarantee that file rules already
// provide: those checks cannot be weakened by configuration.
var suppressibleRuleIDs = map[string]bool{
	"inline-interpreter-code": true,
}

func prepareSuppressions(suppressions []Suppression, baseDir string) error {
	for i := range suppressions {
		suppression := &suppressions[i]
		if suppression.RuleID == "" {
			return fmt.Errorf("suppress entry %d must specify rule_id", i+1)
		}
		if !suppressibleRuleIDs[suppression.RuleID] {
			return fmt.Errorf("suppress entry %d has rule_id %q, which is not suppressible", i+1, suppression.RuleID)
		}
		suppression.commandSet = make(map[string]bool, len(suppression.Commands))
		for _, command := range suppression.Commands {
			if strings.TrimSpace(command) == "" {
				return fmt.Errorf("suppress entry %d must not contain an empty command", i+1)
			}
			suppression.commandSet[command] = true
		}
		for j, directory := range suppression.Directories {
			expanded, err := expandConfigPath(directory, baseDir)
			if err != nil {
				return fmt.Errorf("suppress entry %d directory: %w", i+1, err)
			}
			suppression.Directories[j] = expanded
		}
	}
	return nil
}

// suppresses reports whether a finding is silenced by configuration. A block
// decision is never suppressed, so adding a block rule to suppressibleRuleIDs
// cannot silently disable a hard stop.
func (a *analyzer) suppresses(decision Decision, ruleID, command string) bool {
	if decision == Block || len(a.suppressions) == 0 {
		return false
	}
	cwd := a.cwd
	if absolute, err := filepath.Abs(cwd); err == nil {
		cwd = filepath.Clean(absolute)
	}
	for i := range a.suppressions {
		suppression := &a.suppressions[i]
		if suppression.RuleID != ruleID {
			continue
		}
		if len(suppression.Commands) > 0 && !suppression.matchesCommand(command) {
			continue
		}
		if len(suppression.Directories) > 0 && !inAnyDirectory(cwd, suppression.Directories) {
			continue
		}
		return true
	}
	return false
}

func (s Suppression) matchesCommand(command string) bool {
	if s.commandSet != nil {
		return s.commandSet[command]
	}
	for _, configured := range s.Commands {
		if configured == command {
			return true
		}
	}
	return false
}

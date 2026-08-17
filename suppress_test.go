package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSuppressionSilencesConfiguredCommand(t *testing.T) {
	root := t.TempDir()
	config := Config{Suppressions: []Suppression{
		{RuleID: "inline-interpreter-code", Commands: []string{"python3"}},
	}}
	if err := config.prepare(root); err != nil {
		t.Fatal(err)
	}

	suppressed := analyzePOSIXWithConfig(`python3 -c "import json;print(1)"`, root, config)
	if suppressed.Decision != Allow || hasRule(suppressed, "inline-interpreter-code") {
		t.Fatalf("configured command: got decision=%s findings=%+v", suppressed.Decision, suppressed.Findings)
	}

	untouched := analyzePOSIXWithConfig(`node -e "console.log(1)"`, root, config)
	if untouched.Decision != Review || !hasRule(untouched, "inline-interpreter-code") {
		t.Fatalf("command outside the entry: got decision=%s findings=%+v", untouched.Decision, untouched.Findings)
	}
}

func TestSuppressionWithoutCommandsAppliesToEveryInterpreter(t *testing.T) {
	root := t.TempDir()
	config := Config{Suppressions: []Suppression{{RuleID: "inline-interpreter-code"}}}
	if err := config.prepare(root); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{`python3 -c "print(1)"`, `node -e "console.log(1)"`, `ruby -e "puts 1"`} {
		result := analyzePOSIXWithConfig(command, root, config)
		if result.Decision != Allow || hasRule(result, "inline-interpreter-code") {
			t.Errorf("%q: got decision=%s findings=%+v", command, result.Decision, result.Findings)
		}
	}
}

// A suppression must not behave like an allow rule: the shell input is still
// parsed, so every other command in a compound statement keeps its decision.
// This is the property a regex-based allow rule cannot provide.
func TestSuppressionKeepsFindingsFromOtherCommands(t *testing.T) {
	root := t.TempDir()
	config := Config{Suppressions: []Suppression{{RuleID: "inline-interpreter-code"}}}
	if err := config.prepare(root); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		command string
		rule    string
	}{
		{"and-list", `python3 -c "print(1)" && sudo rm -rf /etc`, "privilege-escalation"},
		{"semicolon", `python3 -c "print(1)" ; sudo rm -rf /etc`, "privilege-escalation"},
		{"newline", "python3 -c \"print(1)\"\nsudo rm -rf /etc", "privilege-escalation"},
		{"pipeline", `python3 -c "print(1)" | sudo tee /etc/hosts`, "privilege-escalation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := analyzePOSIXWithConfig(test.command, root, config)
			if result.Decision != Block {
				t.Fatalf("got decision=%s, want block; findings=%+v", result.Decision, result.Findings)
			}
			if !hasRule(result, test.rule) {
				t.Fatalf("missing %q; findings=%+v", test.rule, result.Findings)
			}
			if hasRule(result, "inline-interpreter-code") {
				t.Fatalf("suppressed finding was reported; findings=%+v", result.Findings)
			}
		})
	}
}

func TestSuppressionDirectoryScope(t *testing.T) {
	root := t.TempDir()
	trusted := filepath.Join(root, "trusted")
	config := Config{Suppressions: []Suppression{
		{RuleID: "inline-interpreter-code", Directories: []string{trusted}},
	}}
	if err := config.prepare(root); err != nil {
		t.Fatal(err)
	}

	inside := analyzePOSIXWithConfig(`python3 -c "print(1)"`, filepath.Join(trusted, "child"), config)
	if inside.Decision != Allow || hasRule(inside, "inline-interpreter-code") {
		t.Fatalf("inside trusted directory: got decision=%s findings=%+v", inside.Decision, inside.Findings)
	}

	outside := analyzePOSIXWithConfig(`python3 -c "print(1)"`, filepath.Join(root, "trusted-other"), config)
	if outside.Decision != Review || !hasRule(outside, "inline-interpreter-code") {
		t.Fatalf("outside trusted directory: got decision=%s findings=%+v", outside.Decision, outside.Findings)
	}
}

// Even if a block rule is added to the suppressible set, a block decision must
// survive. Suppression is only ever allowed to silence a review.
func TestSuppressionNeverSilencesBlock(t *testing.T) {
	const ruleID = "privilege-escalation"
	suppressibleRuleIDs[ruleID] = true
	t.Cleanup(func() { delete(suppressibleRuleIDs, ruleID) })

	root := t.TempDir()
	config := Config{Suppressions: []Suppression{{RuleID: ruleID}}}
	if err := config.prepare(root); err != nil {
		t.Fatal(err)
	}
	result := analyzePOSIXWithConfig("sudo rm -rf /etc", root, config)
	if result.Decision != Block || !hasRule(result, ruleID) {
		t.Fatalf("got decision=%s findings=%+v", result.Decision, result.Findings)
	}
}

func TestSuppressionIsNotAppliedToFilePolicy(t *testing.T) {
	const ruleID = "sensitive-file-write"
	if suppressibleRuleIDs[ruleID] {
		t.Fatalf("%q must not be suppressible", ruleID)
	}
	config := Config{Suppressions: []Suppression{{RuleID: ruleID}}}
	if err := config.prepare(t.TempDir()); err == nil {
		t.Fatal("a non-suppressible rule id was accepted")
	}
}

func TestInvalidSuppression(t *testing.T) {
	tests := []struct {
		name        string
		suppression Suppression
	}{
		{"missing rule id", Suppression{Commands: []string{"python3"}}},
		{"non-suppressible rule id", Suppression{RuleID: "recursive-delete-protected"}},
		{"unknown rule id", Suppression{RuleID: "no-such-rule"}},
		{"empty command", Suppression{RuleID: "inline-interpreter-code", Commands: []string{" "}}},
		{"empty directory", Suppression{RuleID: "inline-interpreter-code", Directories: []string{""}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{Suppressions: []Suppression{test.suppression}}
			if err := config.prepare(t.TempDir()); err == nil {
				t.Fatal("invalid suppression was accepted")
			}
		})
	}
}

func TestLoadConfigWithSuppression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	contents := []byte(`[[suppress]]
rule_id = "inline-interpreter-code"
commands = ["python3", "node"]
directories = ["./workspace", "~/trusted"]
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Suppressions) != 1 {
		t.Fatalf("suppressions: got %d, want 1", len(config.Suppressions))
	}
	suppression := config.Suppressions[0]
	if got := suppression.Directories[0]; got != filepath.Join(dir, "workspace") {
		t.Fatalf("relative directory: got %q", got)
	}
	if !suppression.matchesCommand("python3") || suppression.matchesCommand("ruby") {
		t.Fatalf("command set: got %v", suppression.Commands)
	}
}

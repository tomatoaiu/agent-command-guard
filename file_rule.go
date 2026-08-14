package main

import (
	"fmt"
)

// FileRule is a structured policy for one or more direct file operations.
// Roots identify target paths, while Directories optionally restrict the
// caller working directories where the rule applies.
type FileRule struct {
	ID          string          `toml:"id"`
	Action      Decision        `toml:"action"`
	Operations  []FileOperation `toml:"operations"`
	Roots       []string        `toml:"roots"`
	Directories []string        `toml:"directories"`

	operationSet        map[FileOperation]bool
	resolvedRoots       []string
	resolvedDirectories []string
}

func prepareFileRules(rules []FileRule, baseDir string, seen map[string]bool) error {
	for i := range rules {
		rule := &rules[i]
		if rule.ID == "" {
			rule.ID = fmt.Sprintf("custom-file-rule-%d", i+1)
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Action != Allow && rule.Action != Review && rule.Action != Block {
			return fmt.Errorf("file rule %q has invalid action %q", rule.ID, rule.Action)
		}
		if len(rule.Operations) == 0 {
			return fmt.Errorf("file rule %q must specify operations", rule.ID)
		}
		rule.operationSet = make(map[FileOperation]bool, len(rule.Operations))
		for _, operation := range rule.Operations {
			if operation != FileRead && operation != FileEdit && operation != FileWrite {
				return fmt.Errorf("file rule %q has invalid operation %q", rule.ID, operation)
			}
			if rule.operationSet[operation] {
				return fmt.Errorf("file rule %q has duplicate operation %q", rule.ID, operation)
			}
			rule.operationSet[operation] = true
		}
		if len(rule.Roots) == 0 {
			return fmt.Errorf("file rule %q must specify roots", rule.ID)
		}
		rule.resolvedRoots = make([]string, len(rule.Roots))
		for j, root := range rule.Roots {
			expanded, err := expandConfigPath(root, baseDir)
			if err != nil {
				return fmt.Errorf("file rule %q root: %w", rule.ID, err)
			}
			rule.Roots[j] = expanded
			rule.resolvedRoots[j] = resolvePathSymlinks(expanded)
		}
		rule.resolvedDirectories = make([]string, len(rule.Directories))
		for j, directory := range rule.Directories {
			expanded, err := expandConfigPath(directory, baseDir)
			if err != nil {
				return fmt.Errorf("file rule %q directory: %w", rule.ID, err)
			}
			rule.Directories[j] = expanded
			rule.resolvedDirectories[j] = resolvePathSymlinks(expanded)
		}
	}
	return nil
}

func (r FileRule) includesOperation(operation FileOperation) bool {
	if r.operationSet != nil {
		return r.operationSet[operation]
	}
	for _, configured := range r.Operations {
		if configured == operation {
			return true
		}
	}
	return false
}

func (c Config) matchFile(operation FileOperation, normalized, resolved, cwd, resolvedCWD string) *FileRule {
	for i := range c.FileRules {
		rule := &c.FileRules[i]
		if !rule.includesOperation(operation) || !matchesConfiguredPaths(normalized, resolved, rule.Roots, rule.resolvedRoots) {
			continue
		}
		if len(rule.Directories) > 0 && !matchesConfiguredPaths(cwd, resolvedCWD, rule.Directories, rule.resolvedDirectories) {
			continue
		}
		return rule
	}
	return nil
}

// matchesConfiguredPaths requires both the normalized path and its resolved
// longest existing prefix to remain inside the corresponding configured root.
// This prevents a symlink below an allowed root from escaping the rule.
func matchesConfiguredPaths(normalized, resolved string, roots, resolvedRoots []string) bool {
	for i, root := range roots {
		resolvedRoot := resolvePathSymlinks(root)
		if i < len(resolvedRoots) && resolvedRoots[i] != "" {
			resolvedRoot = resolvedRoots[i]
		}
		if filePathWithin(normalized, root) && filePathWithin(resolved, resolvedRoot) {
			return true
		}
	}
	return false
}

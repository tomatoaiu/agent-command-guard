package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Git    GitConfig    `toml:"git"`
	Output OutputConfig `toml:"output"`
	Rules  []Rule       `toml:"rules"`
}

type OutputConfig struct {
	Language string `toml:"language"`
}

type GitConfig struct {
	ProtectedBranches []string `toml:"protected_branches"`
}

type Rule struct {
	ID          string   `toml:"id"`
	Action      Decision `toml:"action"`
	Command     string   `toml:"command"`
	Directories []string `toml:"directories"`

	commandPattern *regexp.Regexp
}

func DefaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent-command-guard", "config.toml"), nil
}

// LoadConfig loads a TOML policy. A missing default policy is treated as an
// empty policy, while an explicitly supplied path must exist.
func LoadConfig(path string, explicit bool) (Config, error) {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return Config{}, fmt.Errorf("resolve config path: %w", err)
		}
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	var config Config
	decoder := toml.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := config.prepare(filepath.Dir(path)); err != nil {
		return Config{}, fmt.Errorf("validate config %q: %w", path, err)
	}
	return config, nil
}

func (c *Config) prepare(baseDir string) error {
	if c.Output.Language == "" {
		c.Output.Language = "en"
	}
	if c.Output.Language != "en" && c.Output.Language != "ja" {
		return fmt.Errorf("output.language must be \"en\" or \"ja\", got %q", c.Output.Language)
	}
	for _, pattern := range c.Git.ProtectedBranches {
		if pattern == "" {
			return errors.New("git.protected_branches must not contain an empty pattern")
		}
		if _, err := filepath.Match(pattern, "branch"); err != nil {
			return fmt.Errorf("invalid protected branch pattern %q: %w", pattern, err)
		}
	}
	seen := make(map[string]bool)
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.ID == "" {
			rule.ID = fmt.Sprintf("custom-rule-%d", i+1)
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Action != Allow && rule.Action != Review && rule.Action != Block {
			return fmt.Errorf("rule %q has invalid action %q", rule.ID, rule.Action)
		}
		if rule.Command == "" && len(rule.Directories) == 0 {
			return fmt.Errorf("rule %q must specify command or directories", rule.ID)
		}
		if rule.Command != "" {
			pattern, err := regexp.Compile("^(?:" + rule.Command + ")$")
			if err != nil {
				return fmt.Errorf("rule %q has invalid command regex: %w", rule.ID, err)
			}
			rule.commandPattern = pattern
		}
		for j, directory := range rule.Directories {
			expanded, err := expandConfigPath(directory, baseDir)
			if err != nil {
				return fmt.Errorf("rule %q: %w", rule.ID, err)
			}
			rule.Directories[j] = expanded
		}
	}
	return nil
}

func expandConfigPath(path, baseDir string) (string, error) {
	if path == "" {
		return "", errors.New("directory must not be empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand %q: %w", path, err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return filepath.Clean(path), nil
}

func (c Config) match(command, cwd string) *Rule {
	command = strings.TrimSpace(command)
	cwd, _ = filepath.Abs(cwd)
	cwd = filepath.Clean(cwd)
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.commandPattern != nil && !rule.commandPattern.MatchString(command) {
			continue
		}
		if len(rule.Directories) > 0 && !inAnyDirectory(cwd, rule.Directories) {
			continue
		}
		return rule
	}
	return nil
}

func inAnyDirectory(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

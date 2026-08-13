package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

type ShellDialect string

const (
	ShellAuto       ShellDialect = "auto"
	ShellPOSIX      ShellDialect = "posix"
	ShellPowerShell ShellDialect = "powershell"
)

func parseShellDialect(value string) (ShellDialect, error) {
	shell := ShellDialect(strings.ToLower(strings.TrimSpace(value)))
	switch shell {
	case ShellAuto, ShellPOSIX, ShellPowerShell:
		return shell, nil
	default:
		return "", fmt.Errorf("shell must be auto, posix, or powershell, got %q", value)
	}
}

func (s ShellDialect) resolved() ShellDialect {
	if s != ShellAuto {
		return s
	}
	if runtime.GOOS == "windows" {
		return ShellPowerShell
	}
	return ShellPOSIX
}

func userHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return os.Getenv("USERPROFILE")
}

func normalizeCommandName(command string) string {
	command = strings.TrimSpace(command)
	if index := strings.LastIndexAny(command, `/\`); index >= 0 {
		command = command[index+1:]
	}
	command = strings.ToLower(command)
	for _, extension := range []string{".exe", ".cmd", ".bat", ".com"} {
		if strings.HasSuffix(command, extension) {
			return strings.TrimSuffix(command, extension)
		}
	}
	return command
}

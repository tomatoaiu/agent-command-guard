package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func gitCommand(cwd string, args ...string) *exec.Cmd {
	executable := trustedGitExecutable()
	if executable == "" {
		executable = "agent-command-guard-git-not-found"
	}
	commandArgs := append([]string{"-C", cwd}, args...)
	command := exec.Command(executable, commandArgs...)
	if runtime.GOOS != "windows" && executable == "/usr/bin/git" {
		command.Env = []string{"PATH=/usr/bin:/bin"}
	}
	return command
}

func trustedGitExecutable() string {
	if runtime.GOOS != "windows" {
		if info, err := os.Stat("/usr/bin/git"); err == nil && !info.IsDir() {
			return "/usr/bin/git"
		}
	}
	if runtime.GOOS == "windows" {
		candidates := []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Git", "cmd", "git.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "git.exe"),
			filepath.Join(os.Getenv("LocalAppData"), "Programs", "Git", "cmd", "git.exe"),
		}
		for _, candidate := range candidates {
			if filepath.IsAbs(candidate) {
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					return candidate
				}
			}
		}
	}
	path, err := exec.LookPath("git")
	if err == nil && filepath.IsAbs(path) {
		return path
	}
	return ""
}

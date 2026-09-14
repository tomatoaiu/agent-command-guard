package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type MacOSConfig struct {
	TrustedOSAScriptFiles []string `toml:"trusted_osascript_files"`

	resolvedTrustedOSAScriptFiles []string
}

func prepareMacOSConfig(config *MacOSConfig, baseDir string) error {
	config.resolvedTrustedOSAScriptFiles = make([]string, len(config.TrustedOSAScriptFiles))
	for i, file := range config.TrustedOSAScriptFiles {
		expanded, err := expandConfigPath(file, baseDir)
		if err != nil {
			return fmt.Errorf("macos.trusted_osascript_files: %w", err)
		}
		config.TrustedOSAScriptFiles[i] = expanded
		config.resolvedTrustedOSAScriptFiles[i] = resolvePathSymlinks(expanded)
	}
	return nil
}

func (a *analyzer) trustedOSAScriptInvocation(args []string, known []bool) bool {
	for i := 0; i < len(args); i++ {
		if i >= len(known) || !known[i] {
			return false
		}
		arg := args[i]
		switch {
		case arg == "--":
			i++
			if i >= len(args) || i >= len(known) || !known[i] {
				return false
			}
			return a.trustedOSAScriptPath(args[i])
		case arg == "-e" || strings.HasPrefix(arg, "-e") && len(arg) > 2:
			return false
		case arg == "-l":
			// The file was reviewed for osascript's default AppleScript
			// interpreter. Reinterpreting the same bytes as JavaScript is a
			// different executable payload.
			return false
		case arg == "-s":
			i++
			if i >= len(args) || i >= len(known) || !known[i] {
				return false
			}
		case arg == "-i":
			return false
		case strings.HasPrefix(arg, "-"):
			return false
		default:
			return a.trustedOSAScriptPath(arg)
		}
	}
	return false
}

func (a *analyzer) trustedOSAScriptPath(path string) bool {
	cwd := a.cwd
	if a.commandCWDSet {
		if !a.commandCWDKnown {
			return false
		}
		cwd = a.commandCWD
	}
	if path == "~" {
		path = a.home
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(a.home, path[2:])
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	resolved := resolvePathSymlinks(path)
	for i, trusted := range a.trustedOSAScriptFiles {
		resolvedTrusted := resolvePathSymlinks(trusted)
		if i < len(a.resolvedTrustedOSAScriptFiles) && a.resolvedTrustedOSAScriptFiles[i] != "" {
			resolvedTrusted = a.resolvedTrustedOSAScriptFiles[i]
		}
		if samePath(path, trusted) && samePath(resolved, resolvedTrusted) {
			return true
		}
	}
	return false
}

package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A DNS lookup leaves the machine even when nothing else does, so a name built
// by running a command is a way to carry that command's output out over DNS.
// A name held in a variable is not treated the same way: variables are how
// ordinary scripts pass a hostname around.
func dnsLookupCommand(command string) bool {
	switch command {
	case "dig", "drill", "host", "nslookup":
		return true
	}
	return false
}

func wordHasCommandSubstitution(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.CmdSubst); ok {
			found = true
			return false
		}
		return !found
	})
	return found
}

// Opening a URL hands the address to the browser, which carries the session
// cookies the shell does not have. That makes it a way to move data out under
// the user's own identity.
func opensRemoteURL(args []string, known []bool) bool {
	for i, arg := range args {
		if i < len(known) && !known[i] {
			continue
		}
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			return true
		}
	}
	return false
}

// A bind mount gives the container the host's filesystem, so the isolation
// that makes running an unknown image acceptable is no longer there.
func containerMountsHost(command string, args []string) bool {
	switch command {
	case "docker", "podman", "nerdctl":
	default:
		return false
	}
	if firstSubcommand(args) != "run" && firstSubcommand(args) != "create" {
		return false
	}
	return containsAny(args, "-v", "--volume", "--mount") ||
		anyArgPrefix(args, "--volume=") || anyArgPrefix(args, "--mount=")
}

// Variables that decide which binaries run, where the home directory is, or
// which proxy the traffic goes through.
var overridableEnvironmentNames = map[string]bool{
	"EDITOR": true,
	"HOME":   true,
	"SHELL":  true,
	"USER":   true,
	"VISUAL": true,
}

var proxyEnvironmentNames = map[string]bool{
	"all_proxy":   true,
	"ftp_proxy":   true,
	"http_proxy":  true,
	"https_proxy": true,
	"no_proxy":    true,
}

// Returns the rule that fits the assignment, or an empty string when the name
// being assigned does not decide what runs or where traffic goes.
func environmentOverrideRule(name string, valueKnown bool) string {
	if proxyEnvironmentNames[strings.ToLower(name)] {
		return "proxy-override"
	}
	if overridableEnvironmentNames[name] {
		return "environment-override"
	}
	// A PATH built from the existing one is an append, which is how every
	// shell profile extends it. Only a value the analyzer can resolve on its
	// own replaces PATH outright.
	if name == "PATH" && valueKnown {
		return "path-override"
	}
	return ""
}

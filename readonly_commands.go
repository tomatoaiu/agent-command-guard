package main

import "strings"

// Several macOS administration tools read and write through the same command
// name, so blocking on the name alone stops ordinary inspection along with the
// dangerous edits. Each helper below proves that an invocation only reads;
// anything it cannot prove — an unknown flag, or an argument whose value the
// analyzer could not resolve — keeps the blanket block.

// nvram is both a reader and a writer of firmware variables, so the command
// name alone says nothing about intent.
//
//	read:  nvram <name> / nvram -p / nvram -x -p
//	write: nvram <name>=<value> / nvram -d <name> / nvram -c / nvram -f <file>
//
// Only the forms that can be proven to read are allowed; anything else,
// including an argument the analyzer cannot resolve, stays blocked.
func nvramReadsOnly(args []string, known []bool) bool {
	for i, arg := range args {
		if i >= len(known) || !known[i] {
			return false
		}
		if strings.HasPrefix(arg, "-") {
			if !nvramReadOnlyFlag(arg) {
				return false
			}
			continue
		}
		if strings.Contains(arg, "=") {
			return false
		}
	}
	return true
}

// -p prints every variable and -x switches the output to XML; neither changes
// anything. Both are single letters, so a bundle such as -xp is read-only too.
func nvramReadOnlyFlag(arg string) bool {
	letters := strings.TrimPrefix(arg, "-")
	if letters == "" {
		return false
	}
	for _, letter := range letters {
		if letter != 'p' && letter != 'x' {
			return false
		}
	}
	return true
}

// csrutil reports System Integrity Protection through "status" and changes it
// through every other subcommand, including "disable", "clear", and
// "authenticated-root". Only "status" reads.
func csrutilReadsOnly(args []string, known []bool) bool {
	for i, arg := range args {
		if i >= len(known) || !known[i] || arg != "status" {
			return false
		}
	}
	return true
}

// dscl read verbs. "-search" queries, "-list" enumerates, and the "-read"
// family prints records. Everything else in dscl — -create, -delete, -append,
// -merge, -change, -passwd and their plist variants — edits the directory.
var dsclReadVerbs = map[string]bool{
	"-list":    true,
	"-plist":   true,
	"-read":    true,
	"-readall": true,
	"-readpl":  true,
	"-search":  true,
}

// Flags that only shape dscl's output. "-u" and "-P" are deliberately absent:
// they carry an account name and a password, so an invocation using them is
// authenticating rather than reading as the current user.
var dsclNeutralFlags = map[string]bool{
	"-q":   true,
	"-raw": true,
	"-url": true,
}

// A dscl invocation reads only when every flag it passes is a read verb or an
// output-shaping flag, and at least one of them actually is a read verb --
// bare "dscl <node>" opens an interactive prompt that can then write.
func dsclReadsOnly(args []string, known []bool) bool {
	readVerb := false
	for i, arg := range args {
		if i >= len(known) || !known[i] {
			return false
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		if dsclReadVerbs[arg] {
			readVerb = true
			continue
		}
		if !dsclNeutralFlags[arg] {
			return false
		}
	}
	return readVerb
}

// networksetup names every subcommand as a flag, and the naming is consistent:
// -list… enumerates, -get… reports, and everything else (-set…, -create…,
// -delete…, -add…, -remove…, -order…) reconfigures the network.
func networksetupReadsOnly(args []string, known []bool) bool {
	reader := false
	for i, arg := range args {
		if i >= len(known) || !known[i] {
			return false
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		if !strings.HasPrefix(arg, "-list") && !strings.HasPrefix(arg, "-get") {
			return false
		}
		reader = true
	}
	return reader
}

package main

import (
	"path/filepath"
	"strings"
)

// Directories that exist to hold credentials. sensitiveReadPath recognises the
// individual files inside them, which is enough to stop a read; a transfer or
// an archive names the directory instead, and would otherwise carry every key
// in it past a check that only ever looked at filenames.
var credentialDirectories = []string{
	".aws",
	".azure",
	".gnupg",
	".kube",
	".ssh",
	filepath.Join(".config", "gcloud"),
	filepath.Join(".config", "gh"),
}

func (a *analyzer) sensitiveTree(path string) bool {
	if a.sensitiveReadPath(path) {
		return true
	}
	if a.home == "" {
		return false
	}
	normalized := a.normalizePath(path)
	resolved := resolvePathSymlinks(normalized)
	for _, name := range credentialDirectories {
		root := filepath.Join(a.home, name)
		if pathWithin(normalized, root) || pathWithin(resolved, resolvePathSymlinks(root)) {
			return true
		}
	}
	return false
}

// Sending a credential somewhere else cannot be taken back, so it is judged the
// same way reading one is. Without this, changing the verb from cat to scp was
// enough to get the same file past the guard.
func (a *analyzer) inspectTransferSources(command string, args []string, known []bool) bool {
	blocked := false
	for i, arg := range args {
		if i >= len(known) || !known[i] || strings.HasPrefix(arg, "-") {
			continue
		}
		if a.sensitiveTree(arg) {
			a.add(Block, "sensitive-remote-transfer", command, a.normalizePath(arg))
			blocked = true
		}
	}
	return blocked
}

func (a *analyzer) archiveSensitiveTarget(args []string, known []bool) (string, bool) {
	for i, arg := range args {
		if i >= len(known) || !known[i] || strings.HasPrefix(arg, "-") {
			continue
		}
		if a.sensitiveTree(arg) {
			return a.normalizePath(arg), true
		}
	}
	return "", false
}

// find's search roots come after its leading options and before the first
// predicate. Predicates start with "-", and grouping starts with "(", "!", or
// ",", so the roots are the plain words in between.
func findSearchRoots(args []string) []int {
	roots := make([]int, 0, len(args))
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if len(roots) > 0 {
				break
			}
			// A leading option such as -L, before any root.
			continue
		}
		if arg == "(" || arg == "!" || arg == "," {
			break
		}
		roots = append(roots, i)
	}
	return roots
}

// "find <path> -delete" removes everything the expression matches beneath the
// path, so a root that rm may not delete recursively must not be reachable
// this way either.
func (a *analyzer) findDeletesDangerousRoot(args []string, known []bool) (string, bool) {
	for _, index := range findSearchRoots(args) {
		if index >= len(known) || !known[index] {
			continue
		}
		target := a.normalizePath(args[index])
		if a.dangerousDeleteTarget(target) {
			return target, true
		}
	}
	return "", false
}

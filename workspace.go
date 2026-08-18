package main

import (
	"os"
	"path/filepath"
	"strings"
)

// sameGitRepository reports whether dir belongs to the same Git repository as
// cwd, including the case where either is a linked worktree of the other.
//
// A linked worktree lives outside the main working tree, so comparing paths
// alone reports every edit inside one as leaving the workspace. Git records the
// shared repository directory for both, so comparing that instead keeps a
// worktree recognised as part of the same workspace.
func sameGitRepository(cwd, dir string) bool {
	current := gitCommonDir(cwd)
	if current == "" {
		return false
	}
	return current == gitCommonDir(dir)
}

// gitCommonDir returns the absolute, canonical path of the repository directory
// shared by a working tree and all of its linked worktrees. It returns an empty
// string when dir is not inside a repository or Git is unavailable, which keeps
// the caller on its existing, stricter decision.
func gitCommonDir(dir string) string {
	output, err := gitCommand(dir, "rev-parse", "--git-common-dir").Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(output))
	if path == "" {
		return ""
	}
	// Older Git versions answer with a path relative to the queried directory.
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	return canonicalFilesystemPath(path)
}

// outsideWorkspace reports whether a write leaves the session's workspace.
// Two locations count as inside it even though neither sits under the working
// directory: a linked worktree of the same repository, and the agent's own
// runtime area, which the agent maintains regardless of where it is running.
func outsideWorkspace(normalized, resolved string, a *analyzer) bool {
	if filePathWithin(resolved, resolvePathSymlinks(a.cwd)) {
		return false
	}
	if agentRuntimePath(normalized, a.home) {
		return false
	}
	return !inSameRepositoryWorktree(normalized, a.cwd)
}

// inSameRepositoryWorktree reports whether a write target outside the current
// working directory still belongs to the same repository, which is the case
// when the session runs from a repository and the target sits in one of its
// linked worktrees (or the other way round). Such a write is not leaving the
// workspace, so it should not be reviewed as if it were.
func inSameRepositoryWorktree(target, cwd string) bool {
	dir := enclosingDirectory(target)
	if dir == "" {
		return false
	}
	return sameGitRepository(cwd, dir)
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// enclosingDirectory returns the closest existing ancestor of a target path so
// that Git can be queried about a file that has not been created yet.
func enclosingDirectory(path string) string {
	dir := filepath.Dir(path)
	for {
		if directoryExists(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

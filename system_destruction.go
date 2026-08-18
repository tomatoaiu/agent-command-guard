package main

import "strings"

// Verbs that make diskutil rewrite a disk, a partition map, or an APFS
// container. Everything else it does — list, info, mount, unmount, verify — is
// left alone. diskutil matches its verbs case-insensitively, so this does too.
var diskutilDestructiveVerbs = map[string]bool{
	"deletecontainer":  true,
	"deletevolume":     true,
	"destroycontainer": true,
	"erasecontainer":   true,
	"erasedisk":        true,
	"eraseoptical":     true,
	"erasevolume":      true,
	"mergepartitions":  true,
	"partitiondisk":    true,
	"randomdisk":       true,
	"reformat":         true,
	"resizevolume":     true,
	"secureerase":      true,
	"splitpartition":   true,
	"zerodisk":         true,
}

func diskutilDestroys(args []string, known []bool) bool {
	for i, arg := range args {
		if i < len(known) && !known[i] {
			continue
		}
		if diskutilDestructiveVerbs[strings.ToLower(arg)] {
			return true
		}
	}
	return false
}

// Commands that only exist to write a filesystem or a partition table. Their
// names vary by filesystem (mkfs.ext4, newfs_hfs), so they are matched by
// prefix rather than listed exhaustively.
var partitionCommands = map[string]bool{
	"blkdiscard": true,
	"cfdisk":     true,
	"fdisk":      true,
	"gdisk":      true,
	"parted":     true,
	"sfdisk":     true,
	"sgdisk":     true,
	"wipefs":     true,
}

func destroysStorage(command string) bool {
	if partitionCommands[command] {
		return true
	}
	return strings.HasPrefix(command, "mkfs") || strings.HasPrefix(command, "newfs")
}

// Block devices and raw memory. Writing to one of these bypasses the
// filesystem entirely, so a redirection at them is never recoverable.
//
// The character devices a shell legitimately redirects at — /dev/null,
// /dev/stdout, /dev/tty, /dev/fd/N and the like — do not match any of these
// prefixes, so they stay allowed.
var devicePathPrefixes = []string{
	"/dev/disk",
	"/dev/hd",
	"/dev/loop",
	"/dev/md",
	"/dev/mmcblk",
	"/dev/nvme",
	"/dev/rdisk",
	"/dev/sd",
	"/dev/vd",
	"/dev/xvd",
}

func isDevicePath(path string) bool {
	if path == "/dev/mem" || path == "/dev/kmem" || path == "/dev/port" {
		return true
	}
	for _, prefix := range devicePathPrefixes {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		// Require something after the prefix so that a directory named
		// "/dev/sd" alone is not mistaken for a device.
		if len(path) > len(prefix) {
			return true
		}
	}
	return false
}

// The classic fork bomb defines a function named ":" that calls itself twice
// through a pipe. Nothing legitimate defines a function under that name, so
// the declaration itself is the signal, ahead of any invocation.
func forkBombDeclaration(name string) bool {
	return name == ":"
}

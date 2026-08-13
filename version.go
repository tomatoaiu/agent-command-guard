package main

import "runtime/debug"

var releaseVersion string

func versionText() string {
	version := releaseVersion
	if version == "" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	if version == "" {
		version = "dev"
	}
	return "agent-command-guard " + version
}

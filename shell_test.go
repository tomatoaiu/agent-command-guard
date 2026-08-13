package main

import "testing"

func TestParseShellDialect(t *testing.T) {
	for _, value := range []string{"auto", "posix", "powershell", "PoWeRsHeLl"} {
		if _, err := parseShellDialect(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	if _, err := parseShellDialect("cmd"); err == nil {
		t.Fatal("invalid shell was accepted")
	}
}

func TestVersionText(t *testing.T) {
	previous := releaseVersion
	t.Cleanup(func() { releaseVersion = previous })
	releaseVersion = "v1.2.3"
	if got := versionText(); got != "agent-command-guard v1.2.3" {
		t.Fatalf("got %q", got)
	}
}

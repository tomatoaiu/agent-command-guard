package main

import (
	"bytes"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestGoSourcesFormatted(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != "." && (entry.Name() == ".git" || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		normalized := bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
		formatted, err := format.Source(normalized)
		if err != nil {
			t.Errorf("format %s: %v", path, err)
			return nil
		}
		if !bytes.Equal(normalized, formatted) {
			t.Errorf("%s is not gofmt-formatted", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

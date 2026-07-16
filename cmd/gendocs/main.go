package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/vergecloud/cdn-cli/internal/cmd"
	"github.com/vergecloud/cdn-cli/internal/version"
)

func main() {
	outDir := "man"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create man directory: %v\n", err)
		os.Exit(1)
	}

	root := cmd.NewRootCmd()
	header := &doc.GenManHeader{
		Title:   "VERGE",
		Section: "1",
		Manual:  "VergeCloud CDN CLI Manual",
		Source:  fmt.Sprintf("vergecloud-cli %s", version.Version),
	}

	if err := doc.GenManTree(root, header, outDir); err != nil {
		fmt.Fprintf(os.Stderr, "generate man pages: %v\n", err)
		os.Exit(1)
	}

	if err := patchRootManPage(filepath.Join(outDir, "verge.1"), root); err != nil {
		fmt.Fprintf(os.Stderr, "patch root man page: %v\n", err)
		os.Exit(1)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read man directory: %v\n", err)
		os.Exit(1)
	}

	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".1" {
			count++
		}
	}

	fmt.Printf("generated %d man pages in %s\n", count, outDir)
}

func patchRootManPage(path string, root *cobra.Command) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	marker := ".SH OPTIONS"
	idx := strings.Index(string(data), marker)
	if idx == -1 {
		return nil
	}

	var section strings.Builder
	section.WriteString(".SH COMMANDS\n")
	for _, sub := range root.Commands() {
		if sub.Hidden || sub.Name() == "help" {
			continue
		}
		name := sub.Name()
		short := sub.Short
		if short == "" {
			short = sub.Use
		}
		fmt.Fprintf(&section, ".TP\n.B %s\n%s\n", name, short)
	}

	updated := string(data[:idx]) + section.String() + string(data[idx:])
	return os.WriteFile(path, []byte(updated), 0o644)
}

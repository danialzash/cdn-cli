package main

import (
	"fmt"
	"os"
	"path/filepath"

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

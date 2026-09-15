// Command generate-catalog writes the Markdown module reference from the live registry.
package main

import (
	"fmt"
	"os"

	"github.com/0xv1n/macnoise/internal/catalogdoc"
	"github.com/0xv1n/macnoise/pkg/module"

	_ "github.com/0xv1n/macnoise/modules/credential"
	_ "github.com/0xv1n/macnoise/modules/evasion"
	_ "github.com/0xv1n/macnoise/modules/file"
	_ "github.com/0xv1n/macnoise/modules/network"
	_ "github.com/0xv1n/macnoise/modules/plist"
	_ "github.com/0xv1n/macnoise/modules/process"
	_ "github.com/0xv1n/macnoise/modules/service"
	_ "github.com/0xv1n/macnoise/modules/tcc"
	_ "github.com/0xv1n/macnoise/modules/volume"
)

const outputPath = "docs/module-catalog.md"

func main() {
	data, err := catalogdoc.Render(module.All())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll("docs", 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Package demo embeds the fictional demo estate so `wardmap demo` works from
// any install (npm, PyPI, Homebrew, container) without a clone or a token.
package demo

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed *.json
var files embed.FS

// AzureFile is the demo's Azure federated-credential export (its name
// carries the application ID).
const AzureFile = "fic-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.json"

// WriteTo copies the demo files into dir.
func WriteTo(dir string) error {
	entries, err := files.ReadDir(".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		b, err := files.ReadFile(e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Package procmeta collects process metadata from /proc filesystem.
package procmeta

// ProcessMetadata holds structured process information for expression evaluation.
type ProcessMetadata struct {
	Environ     map[string]string // Parsed environment variables
	Args        []string          // Command-line arguments
	CmdlineFull string            // Full command line as single string
}

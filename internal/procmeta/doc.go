// Package procmeta manages process metadata lifecycle.
//
// ProcessMetadata holds environment variables, command-line arguments, and
// full command line for expression evaluation.
//
// Manager provides command-query separation:
//
// Queries (read-only):
//   - Get(pid) - Retrieve metadata
//   - GetError(pid) - Retrieve collection errors
//   - GetIssues(pid) - Retrieve capture warnings
//
// Commands (mutations):
//   - Set(pid, metadata) - Store metadata
//   - SetError(pid, err) - Store collection error
//   - AddIssue(pid, issue) - Add capture warning
//   - Delete(pid) - Clean up on process exit
//   - GetOrCreate(pid) - Atomic get-or-create
//
// Thread-safe with RWMutex for concurrent access.
package procmeta

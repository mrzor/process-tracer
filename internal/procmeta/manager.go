package procmeta

import (
	"sync"
)

// Manager manages process metadata lifecycle.
// It provides command-query separation for metadata access.
type Manager struct {
	mu             sync.RWMutex
	metadata       map[uint32]*ProcessMetadata // PID -> process metadata
	metadataErrors map[uint32]error            // PID -> metadata collection errors
	captureIssues  map[uint32][]string         // PID -> list of warnings/issues
}

// NewManager creates a new process metadata manager.
func NewManager() *Manager {
	return &Manager{
		metadata:       make(map[uint32]*ProcessMetadata),
		metadataErrors: make(map[uint32]error),
		captureIssues:  make(map[uint32][]string),
	}
}

// Get retrieves metadata for a PID (query).
// Returns nil if no metadata exists for this PID.
func (m *Manager) Get(pid uint32) *ProcessMetadata {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metadata[pid]
}

// GetError retrieves the metadata collection error for a PID (query).
// Returns nil if no error exists for this PID.
func (m *Manager) GetError(pid uint32) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metadataErrors[pid]
}

// GetIssues retrieves the capture issues for a PID (query).
// Returns nil if no issues exist for this PID.
func (m *Manager) GetIssues(pid uint32) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.captureIssues[pid]
}

// Set stores metadata for a PID (command).
// If metadata already exists, it is replaced.
func (m *Manager) Set(pid uint32, metadata *ProcessMetadata) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metadata[pid] = metadata
}

// SetError stores a metadata collection error for a PID (command).
func (m *Manager) SetError(pid uint32, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metadataErrors[pid] = err
}

// AddIssue adds a capture issue for a PID (command).
func (m *Manager) AddIssue(pid uint32, issue string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.captureIssues[pid] = append(m.captureIssues[pid], issue)
}

// AddIssues adds multiple capture issues for a PID (command).
func (m *Manager) AddIssues(pid uint32, issues []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.captureIssues[pid] = append(m.captureIssues[pid], issues...)
}

// Delete removes all data for a PID (command).
// This should be called when a process exits.
func (m *Manager) Delete(pid uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.metadata, pid)
	delete(m.metadataErrors, pid)
	delete(m.captureIssues, pid)
}

// GetOrCreate retrieves metadata for a PID, creating it if it doesn't exist (command).
// Returns the metadata (existing or newly created).
func (m *Manager) GetOrCreate(pid uint32) *ProcessMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.metadata[pid] == nil {
		m.metadata[pid] = &ProcessMetadata{
			Environ: make(map[string]string),
		}
	}

	return m.metadata[pid]
}

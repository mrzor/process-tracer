package envreassembler

import (
	"fmt"
	"strings"
	"time"

	"github.com/mrzor/process-tracer/internal/bpf"
)

// ChunkBuffer holds incomplete environment chunk sequences.
type ChunkBuffer struct {
	chunks        map[uint32][]byte
	receivedFinal bool
	truncated     bool
	lastUpdate    time.Time
}

// ChunkReassembler handles reassembly of chunked environment data from execve events.
type ChunkReassembler struct {
	buffers map[uint32]*ChunkBuffer // PID -> chunk buffer
}

// NewChunkReassembler creates a new chunk reassembler.
func NewChunkReassembler() *ChunkReassembler {
	return &ChunkReassembler{
		buffers: make(map[uint32]*ChunkBuffer),
	}
}

// ReassembledData represents the result of chunk reassembly.
type ReassembledData struct {
	Args      []string
	Env       map[string]string
	Truncated bool
	Issues    []string
}

// HandleChunk processes a single environment chunk event.
// Returns the reassembled data if this was the final chunk, or nil if more chunks are expected.
func (r *ChunkReassembler) HandleChunk(chunk *bpf.EnvChunkEvent) (*ReassembledData, error) {
	pid := chunk.Pid

	// Initialize chunk buffer if needed
	if r.buffers[pid] == nil {
		r.buffers[pid] = &ChunkBuffer{
			chunks:     make(map[uint32][]byte),
			lastUpdate: time.Now(),
		}
	}

	buffer := r.buffers[pid]
	buffer.lastUpdate = time.Now()

	// Store this chunk's data
	if chunk.DataSize > 0 {
		buffer.chunks[chunk.ChunkID] = make([]byte, chunk.DataSize)
		copy(buffer.chunks[chunk.ChunkID], chunk.Data[:chunk.DataSize])
	}

	// Check if this is the final chunk
	if chunk.IsFinal != 0 {
		buffer.receivedFinal = true
		if chunk.Truncated != 0 {
			buffer.truncated = true
		}
	}

	// If we've received the final chunk, reassemble and return
	if buffer.receivedFinal {
		result := r.reassembleChunks(pid, buffer)
		delete(r.buffers, pid) // Clean up
		return result, nil
	}

	return nil, nil
}

// reassembleChunks reconstructs argv and environment from chunks.
// This is a pure function that transforms chunk data into structured args and env.
func (r *ChunkReassembler) reassembleChunks(_ uint32, buffer *ChunkBuffer) *ReassembledData {
	result := &ReassembledData{
		Env:       make(map[string]string),
		Truncated: buffer.truncated,
		Issues:    []string{},
	}

	// Reconstruct the full data in chunk order
	var fullData []byte
	numChunks := len(buffer.chunks)
	//nolint:gosec // numChunks is bounded by map size, conversion is safe
	for i := uint32(0); i < uint32(numChunks); i++ {
		if chunkData, exists := buffer.chunks[i]; exists {
			fullData = append(fullData, chunkData...)
		} else {
			// Missing chunk - add issue
			result.Issues = append(result.Issues, fmt.Sprintf("data incomplete: missing chunk %d", i))
			break
		}
	}

	// Parse null-terminated strings
	result.Args, result.Env = parseNullTerminatedStrings(fullData)

	// Add truncation warning if applicable
	if buffer.truncated {
		result.Issues = append(result.Issues, fmt.Sprintf("data truncated: captured %d args, %d env vars", len(result.Args), len(result.Env)))
	}

	return result
}

// parseNullTerminatedStrings parses null-terminated strings from raw data.
// Args come first (no '='), then env vars (KEY=VALUE).
// This is a pure function with no side effects.
func parseNullTerminatedStrings(data []byte) ([]string, map[string]string) {
	var args []string
	env := make(map[string]string)
	offset := 0

	for offset < len(data) {
		// Find the null terminator
		end := offset
		for end < len(data) && data[end] != 0 {
			end++
		}

		if end == offset {
			// Empty string or end of data
			break
		}

		str := string(data[offset:end])

		// Check if this is an environment variable (contains '=')
		if idx := strings.IndexByte(str, '='); idx > 0 {
			// This is an env var
			key := str[:idx]
			value := str[idx+1:]
			env[key] = value
		} else {
			// This is a command-line argument (no '=')
			args = append(args, str)
		}

		offset = end + 1 // Skip the null terminator
	}

	return args, env
}

// Cleanup removes stale chunk buffers that haven't been updated recently.
func (r *ChunkReassembler) Cleanup(maxAge time.Duration) int {
	now := time.Now()
	cleaned := 0

	for pid, buffer := range r.buffers {
		if now.Sub(buffer.lastUpdate) > maxAge {
			delete(r.buffers, pid)
			cleaned++
		}
	}

	return cleaned
}

// Package hasher provides SHA3-based file hashing with streaming I/O.
//
// This package is designed for hashing arbitrarily large files with constant
// memory overhead by using a fixed-size buffer and streaming reads.
package hasher

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

// HashFile streams a file through SHA3-512 using a 4MB buffer for optimal throughput.
// Returns the 64-byte digest. O(1) memory complexity regardless of file size.
//
// The function opens the file in read-only mode, streams its contents through
// a SHA3-512 hasher using a 4MB intermediate buffer, and returns the resulting
// 64-byte digest. File close errors are properly handled and reported.
func HashFile(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("hasher: open file: %w", err)
	}

	hasher := sha3.New512()
	buf := make([]byte, 4*1024*1024) // 4MB buffer for optimal throughput

	if _, err := io.CopyBuffer(hasher, file, buf); err != nil {
		// Attempt to close even on copy failure; report the copy error as primary.
		_ = file.Close()
		return nil, fmt.Errorf("hasher: read file: %w", err)
	}

	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("hasher: close file: %w", err)
	}

	return hasher.Sum(nil), nil
}

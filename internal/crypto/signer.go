package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"
)

// BuildSigningPayload constructs a context-bound signing payload.
//
// It hashes the concatenation of:
//   - fileHash (64 bytes, SHA3-512 digest of the file)
//   - fileSize (8 bytes, big-endian uint64)
//   - filename (UTF-8 encoded)
//   - ":" (separator)
//   - timestamp (RFC3339 string)
//
// Returns a 64-byte SHA3-512 digest of the concatenated binding data.
// This binding ensures that the signature covers not just the file content
// but also its metadata context, preventing substitution attacks.
func BuildSigningPayload(fileHash []byte, fileSize int64, filename string, timestamp string) ([]byte, error) {
	if len(fileHash) != 64 {
		return nil, fmt.Errorf("crypto: invalid file hash length: got %d, want 64", len(fileHash))
	}
	if filename == "" {
		return nil, fmt.Errorf("crypto: filename cannot be empty")
	}
	if timestamp == "" {
		return nil, fmt.Errorf("crypto: timestamp cannot be empty")
	}

	h := sha3.New512()

	// Write file hash (64 bytes)
	h.Write(fileHash)

	// Write file size as big-endian uint64 (8 bytes)
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(fileSize))
	h.Write(sizeBuf)

	// Write filename (UTF-8)
	h.Write([]byte(filename))

	// Write separator
	h.Write([]byte(":"))

	// Write timestamp (RFC3339)
	h.Write([]byte(timestamp))

	return h.Sum(nil), nil
}

// SignPayload signs a 64-byte payload with a Dilithium private key.
//
// The payload must be exactly 64 bytes (the output of BuildSigningPayload).
// Signing uses crypto/rand.Reader for any randomness needed by the scheme.
// Returns the raw Dilithium signature bytes.
func SignPayload(payload []byte, privKey *mode3.PrivateKey) ([]byte, error) {
	if len(payload) != 64 {
		return nil, fmt.Errorf("crypto: invalid payload length: got %d, want 64", len(payload))
	}

	sig, err := privKey.Sign(rand.Reader, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign payload: %w", err)
	}

	return sig, nil
}

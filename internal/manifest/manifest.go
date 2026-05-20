// Package manifest provides JSON-based evidence manifest management for QS-Sealer.
//
// A manifest captures the cryptographic proof of a sealed file, including the
// file hash, Dilithium signature, public key identifier, and optional encryption
// metadata. Manifests are serialized as pretty-printed JSON for human readability
// and machine parseability.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
)

// Manifest represents a sealed evidence manifest containing cryptographic proof.
//
// All fields are populated during the sealing process. When encryption is enabled,
// the EncAlgorithm and EncFile fields are set to record the encryption method
// and the path to the encrypted output file.
type Manifest struct {
	// Version is the manifest format version (e.g., "1.0").
	Version string `json:"version"`

	// Filename is the base name of the sealed file.
	Filename string `json:"filename"`

	// FilePath is the original path to the sealed file.
	FilePath string `json:"filepath"`

	// FileSizeBytes is the size of the original file in bytes.
	FileSizeBytes int64 `json:"file_size_bytes"`

	// Timestamp is the RFC3339-formatted time when the file was sealed.
	Timestamp string `json:"timestamp"`

	// Algorithm is the signature algorithm used (e.g., "dilithium-mode3").
	Algorithm string `json:"algorithm"`

	// SHA3Hash is the hex-encoded SHA3-512 hash of the file contents.
	SHA3Hash string `json:"sha3_512_hash"`

	// Signature is the hex-encoded or base64-encoded Dilithium signature.
	Signature string `json:"signature"`

	// PublicKeyID is the SHA3-256 fingerprint of the signing public key.
	PublicKeyID string `json:"public_key_id"`

	// Encrypted indicates whether the file was also encrypted during sealing.
	Encrypted bool `json:"encrypted"`

	// EncAlgorithm is the encryption algorithm used (e.g., "AES-256-GCM+ML-KEM-768").
	// Only set when Encrypted is true.
	EncAlgorithm string `json:"enc_algorithm,omitempty"`

	// EncFile is the path to the encrypted output file.
	// Only set when Encrypted is true.
	EncFile string `json:"encrypted_file,omitempty"`
}

// Save writes a manifest to disk as pretty-printed JSON.
//
// The output is indented with two spaces for human readability. The file is
// written with 0644 permissions.
func Save(m *Manifest, path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest: marshal JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("manifest: write file: %w", err)
	}

	return nil
}

// Load reads and validates a manifest from a JSON file.
//
// After deserialization, the following fields are validated to be non-empty:
// Version, Filename, SHA3Hash, Signature, PublicKeyID, Algorithm, and Timestamp.
// Returns an error if the file cannot be read, parsed, or if validation fails.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read file: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse JSON: %w", err)
	}

	// Validate required fields
	if m.Version == "" {
		return nil, fmt.Errorf("manifest: missing required field: version")
	}
	if m.Filename == "" {
		return nil, fmt.Errorf("manifest: missing required field: filename")
	}
	if m.SHA3Hash == "" {
		return nil, fmt.Errorf("manifest: missing required field: sha3_512_hash")
	}
	if m.Signature == "" {
		return nil, fmt.Errorf("manifest: missing required field: signature")
	}
	if m.PublicKeyID == "" {
		return nil, fmt.Errorf("manifest: missing required field: public_key_id")
	}
	if m.Algorithm == "" {
		return nil, fmt.Errorf("manifest: missing required field: algorithm")
	}
	if m.Timestamp == "" {
		return nil, fmt.Errorf("manifest: missing required field: timestamp")
	}
	if m.FileSizeBytes < 0 {
		return nil, fmt.Errorf("manifest: invalid file size: cannot be negative")
	}

	return &m, nil
}

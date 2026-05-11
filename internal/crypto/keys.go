// Package crypto provides post-quantum cryptographic operations for QS-Sealer.
//
// This package wraps Dilithium mode3 (ML-DSA) from cloudflare/circl for
// digital signature operations including key generation, PEM serialization,
// payload signing, and signature verification.
package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"
)

// GenerateKeypair generates a new Dilithium mode3 signing keypair.
//
// It uses crypto/rand.Reader as the entropy source for key generation.
// Returns the public key, private key, and any error encountered.
func GenerateKeypair() (*mode3.PublicKey, *mode3.PrivateKey, error) {
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate keypair: %w", err)
	}
	return pub, priv, nil
}

// SavePrivateKeyPEM serializes a Dilithium private key to PEM format.
//
// The file is written with 0600 permissions (owner read/write only) to protect
// the sensitive key material. The PEM block type is "DILITHIUM PRIVATE KEY".
func SavePrivateKeyPEM(key *mode3.PrivateKey, path string) error {
	raw := key.Bytes()
	block := &pem.Block{
		Type:  "DILITHIUM PRIVATE KEY",
		Bytes: raw,
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("crypto: save private key: %w", err)
	}
	return nil
}

// SavePublicKeyPEM serializes a Dilithium public key to PEM format.
//
// The file is written with 0644 permissions. The PEM block type is
// "DILITHIUM PUBLIC KEY".
func SavePublicKeyPEM(key *mode3.PublicKey, path string) error {
	raw := key.Bytes()
	block := &pem.Block{
		Type:  "DILITHIUM PUBLIC KEY",
		Bytes: raw,
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("crypto: save public key: %w", err)
	}
	return nil
}

// LoadPrivateKeyPEM loads a Dilithium private key from a PEM file.
//
// The file must contain a valid PEM block with type "DILITHIUM PRIVATE KEY".
// The raw bytes are deserialized into a mode3.PrivateKey using UnmarshalBinary.
func LoadPrivateKeyPEM(path string) (*mode3.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto: decode PEM: no valid PEM block found in %s", path)
	}
	if block.Type != "DILITHIUM PRIVATE KEY" {
		return nil, fmt.Errorf("crypto: unexpected PEM type %q, expected DILITHIUM PRIVATE KEY", block.Type)
	}

	var key mode3.PrivateKey
	if err := key.UnmarshalBinary(block.Bytes); err != nil {
		return nil, fmt.Errorf("crypto: unmarshal private key: %w", err)
	}
	return &key, nil
}

// LoadPublicKeyPEM loads a Dilithium public key from a PEM file.
//
// The file must contain a valid PEM block with type "DILITHIUM PUBLIC KEY".
// The raw bytes are deserialized into a mode3.PublicKey using UnmarshalBinary.
func LoadPublicKeyPEM(path string) (*mode3.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto: decode PEM: no valid PEM block found in %s", path)
	}
	if block.Type != "DILITHIUM PUBLIC KEY" {
		return nil, fmt.Errorf("crypto: unexpected PEM type %q, expected DILITHIUM PUBLIC KEY", block.Type)
	}

	var key mode3.PublicKey
	if err := key.UnmarshalBinary(block.Bytes); err != nil {
		return nil, fmt.Errorf("crypto: unmarshal public key: %w", err)
	}
	return &key, nil
}

// PublicKeyID computes a SHA3-256 fingerprint of the public key, returned as a hex string.
//
// This provides a compact, deterministic identifier for a public key that can
// be used to associate signatures with their corresponding verification key.
func PublicKeyID(key *mode3.PublicKey) string {
	h := sha3.New256()
	h.Write(key.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

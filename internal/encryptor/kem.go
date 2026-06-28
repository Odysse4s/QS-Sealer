// Package encryptor provides post-quantum hybrid encryption for QS-Sealer.
//
// This package combines ML-KEM-768 (FIPS 203) key encapsulation with
// AES-256-GCM authenticated encryption to provide quantum-resistant
// file encryption with streaming chunk-based processing.
package encryptor

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// GenerateEncryptionKeypair generates a new ML-KEM-768 key encapsulation keypair.
//
// Returns the public key (for encapsulation) and private key (for decapsulation),
// or an error if key generation fails.
func GenerateEncryptionKeypair() (kem.PublicKey, kem.PrivateKey, error) {
	pub, priv, err := mlkem768.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("encryptor: generate KEM keypair: %w", err)
	}
	return pub, priv, nil
}

// SaveEncPublicKeyPEM saves an ML-KEM public key to PEM format.
//
// The file is written with 0644 permissions. The PEM block type is
// "MLKEM768 PUBLIC KEY".
func SaveEncPublicKeyPEM(key kem.PublicKey, path string) error {
	raw, err := key.MarshalBinary()
	if err != nil {
		return fmt.Errorf("encryptor: marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "MLKEM768 PUBLIC KEY",
		Bytes: raw,
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("encryptor: save public key: %w", err)
	}
	return nil
}

// SaveEncPrivateKeyPEM saves an ML-KEM private key to PEM format.
//
// The file is written with 0600 permissions (owner read/write only) to protect
// the sensitive key material. The PEM block type is "MLKEM768 PRIVATE KEY".
func SaveEncPrivateKeyPEM(key kem.PrivateKey, path string) error {
	raw, err := key.MarshalBinary()
	if err != nil {
		return fmt.Errorf("encryptor: marshal private key: %w", err)
	}
	defer zeroizeKEM(raw)

	block := &pem.Block{
		Type:  "MLKEM768 PRIVATE KEY",
		Bytes: raw,
	}
	data := pem.EncodeToMemory(block)
	defer zeroizeKEM(data)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("encryptor: save private key: %w", err)
	}
	return nil
}

// LoadEncPublicKeyPEM loads an ML-KEM public key from a PEM file.
//
// The file must contain a valid PEM block with type "MLKEM768 PUBLIC KEY".
// The raw bytes are deserialized using the ML-KEM-768 scheme's unmarshaler.
func LoadEncPublicKeyPEM(path string) (kem.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("encryptor: read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("encryptor: decode PEM: no valid PEM block found in %s", path)
	}
	if block.Type != "MLKEM768 PUBLIC KEY" {
		return nil, fmt.Errorf("encryptor: unexpected PEM type %q, expected MLKEM768 PUBLIC KEY", block.Type)
	}

	pub, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("encryptor: unmarshal public key: %w", err)
	}
	return pub, nil
}

// LoadEncPrivateKeyPEM loads an ML-KEM private key from a PEM file.
//
// The file must contain a valid PEM block with type "MLKEM768 PRIVATE KEY".
// The raw bytes are deserialized using the ML-KEM-768 scheme's unmarshaler.
func LoadEncPrivateKeyPEM(path string) (kem.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("encryptor: read private key file: %w", err)
	}
	defer zeroizeKEM(data)

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("encryptor: decode PEM: no valid PEM block found in %s", path)
	}
	if block.Type != "MLKEM768 PRIVATE KEY" {
		return nil, fmt.Errorf("encryptor: unexpected PEM type %q, expected MLKEM768 PRIVATE KEY", block.Type)
	}
	defer zeroizeKEM(block.Bytes)

	priv, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("encryptor: unmarshal private key: %w", err)
	}
	return priv, nil
}

// Encapsulate generates a shared secret and KEM ciphertext using the public key.
//
// The returned ciphertext should be transmitted to the holder of the corresponding
// private key, who can recover the shared secret via Decapsulate. The shared
// secret is suitable for use as a symmetric encryption key (32 bytes for AES-256).
func Encapsulate(pubKey kem.PublicKey) (ciphertext []byte, sharedSecret []byte, err error) {
	ct, ss, err := mlkem768.Scheme().Encapsulate(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encryptor: encapsulate: %w", err)
	}
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from KEM ciphertext using the private key.
//
// Given the ciphertext produced by Encapsulate and the corresponding private key,
// this function recovers the same shared secret that was generated during encapsulation.
func Decapsulate(privKey kem.PrivateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	ss, err := mlkem768.Scheme().Decapsulate(privKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("encryptor: decapsulate: %w", err)
	}
	return ss, nil
}

// zeroizeKEM overwrites a byte slice with zeros to remove sensitive material from memory.
func zeroizeKEM(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

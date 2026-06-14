package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/kem"
)

const (
	// Magic is the file format magic bytes identifying a QS-Sealer encrypted file.
	Magic = "QSSEAL01"
	// Version is the current encrypted file format version.
	Version = 0x01
	// ChunkSize is the plaintext chunk size (1MB) used for streaming encryption.
	ChunkSize = 1 * 1024 * 1024
	// NonceSize is the AES-GCM nonce length in bytes.
	NonceSize = 12
	// TagSize is the GCM authentication tag length in bytes.
	TagSize = 16
	// KEMCTSize is the ML-KEM-768 ciphertext size in bytes.
	KEMCTSize = 1088
)

// EncryptFile encrypts inputPath to outputPath using AES-256-GCM with the given shared secret.
//
// kemCiphertext is the ML-KEM ciphertext to embed in the file header so that the
// recipient can recover the shared secret using their private key.
//
// The file is processed in 1MB chunks for O(1) memory complexity. Each chunk is
// encrypted with a unique nonce derived from a random base nonce XORed with the
// chunk index.
//
// Encrypted file format:
//
//	[8 bytes: magic "QSSEAL01"]
//	[1 byte: version 0x01]
//	[4 bytes: chunk size, big-endian uint32]
//	[1088 bytes: KEM ciphertext]
//	[12 bytes: base nonce (random)]
//	For each chunk:
//	  [4 bytes: encrypted chunk length including GCM tag, big-endian uint32]
//	  [encrypted chunk bytes + 16-byte GCM tag]
//	Terminator: [4 bytes: 0x00000000]
func EncryptFile(inputPath, outputPath string, sharedSecret, kemCiphertext []byte) (err error) {
	if len(sharedSecret) != 32 {
		return fmt.Errorf("encryptor: invalid shared secret length: got %d, want 32", len(sharedSecret))
	}
	if len(kemCiphertext) != KEMCTSize {
		return fmt.Errorf("encryptor: invalid KEM ciphertext length: got %d, want %d", len(kemCiphertext), KEMCTSize)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return fmt.Errorf("encryptor: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("encryptor: create GCM: %w", err)
	}

	// Generate random base nonce
	baseNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return fmt.Errorf("encryptor: generate nonce: %w", err)
	}

	// Open input file
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("encryptor: open input file: %w", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("encryptor: create output file: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("encryptor: close output file: %w", cerr)
		}
	}()

	// Write header: magic (8 bytes)
	if _, err := outFile.Write([]byte(Magic)); err != nil {
		return fmt.Errorf("encryptor: write magic: %w", err)
	}

	// Write version (1 byte)
	if _, err := outFile.Write([]byte{Version}); err != nil {
		return fmt.Errorf("encryptor: write version: %w", err)
	}

	// Write chunk size (4 bytes, big-endian)
	chunkSizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkSizeBuf, uint32(ChunkSize))
	if _, err := outFile.Write(chunkSizeBuf); err != nil {
		return fmt.Errorf("encryptor: write chunk size: %w", err)
	}

	// Write KEM ciphertext (1088 bytes)
	if _, err := outFile.Write(kemCiphertext); err != nil {
		return fmt.Errorf("encryptor: write KEM ciphertext: %w", err)
	}

	// Write base nonce (12 bytes)
	if _, err := outFile.Write(baseNonce); err != nil {
		return fmt.Errorf("encryptor: write base nonce: %w", err)
	}

	// Encrypt and write chunks
	plainBuf := make([]byte, ChunkSize)
	var chunkIndex uint32

	for {
		n, readErr := io.ReadFull(inFile, plainBuf)
		if n > 0 {
			// Derive per-chunk nonce
			nonce := deriveChunkNonce(baseNonce, chunkIndex)

			// Encrypt chunk (output = ciphertext + GCM tag)
			encrypted := gcm.Seal(nil, nonce, plainBuf[:n], nil)

			// Write encrypted chunk length (4 bytes, big-endian)
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
			if _, err := outFile.Write(lenBuf); err != nil {
				return fmt.Errorf("encryptor: write chunk length: %w", err)
			}

			// Write encrypted chunk data
			if _, err := outFile.Write(encrypted); err != nil {
				return fmt.Errorf("encryptor: write encrypted chunk: %w", err)
			}

			chunkIndex++
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("encryptor: read input chunk: %w", readErr)
		}
	}

	// Write terminator (4 zero bytes)
	terminator := make([]byte, 4)
	if _, err := outFile.Write(terminator); err != nil {
		return fmt.Errorf("encryptor: write terminator: %w", err)
	}

	return nil
}

// DecryptFile decrypts inputPath to outputPath using the ML-KEM private key to recover the shared secret.
//
// The function reads the encrypted file header, extracts the KEM ciphertext,
// decapsulates it with the provided private key to recover the AES-256 shared
// secret, then decrypts each chunk using AES-256-GCM with derived per-chunk nonces.
func DecryptFile(inputPath, outputPath string, privKey kem.PrivateKey) error {
	// Open input file
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("encryptor: open encrypted file: %w", err)
	}
	defer inFile.Close()

	// Read and validate magic (8 bytes)
	magicBuf := make([]byte, 8)
	if _, err := io.ReadFull(inFile, magicBuf); err != nil {
		return fmt.Errorf("encryptor: read magic: %w", err)
	}
	if string(magicBuf) != Magic {
		return fmt.Errorf("encryptor: invalid magic: got %q, want %q", string(magicBuf), Magic)
	}

	// Read and validate version (1 byte)
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(inFile, versionBuf); err != nil {
		return fmt.Errorf("encryptor: read version: %w", err)
	}
	if versionBuf[0] != Version {
		return fmt.Errorf("encryptor: unsupported version: got 0x%02x, want 0x%02x", versionBuf[0], Version)
	}

	// Read chunk size (4 bytes, big-endian)
	chunkSizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(inFile, chunkSizeBuf); err != nil {
		return fmt.Errorf("encryptor: read chunk size: %w", err)
	}
	chunkSize := binary.BigEndian.Uint32(chunkSizeBuf)

	// Read KEM ciphertext (1088 bytes)
	kemCT := make([]byte, KEMCTSize)
	if _, err := io.ReadFull(inFile, kemCT); err != nil {
		return fmt.Errorf("encryptor: read KEM ciphertext: %w", err)
	}

	// Read base nonce (12 bytes)
	baseNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(inFile, baseNonce); err != nil {
		return fmt.Errorf("encryptor: read base nonce: %w", err)
	}

	// Decapsulate to recover shared secret
	sharedSecret, err := Decapsulate(privKey, kemCT)
	if err != nil {
		return fmt.Errorf("encryptor: recover shared secret: %w", err)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return fmt.Errorf("encryptor: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("encryptor: create GCM: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("encryptor: create output file: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("encryptor: close output file: %w", cerr)
		}
	}()

	// Decrypt chunks
	// Maximum encrypted chunk size = plaintext chunk size + GCM tag
	maxEncChunkSize := chunkSize + uint32(TagSize)
	encBuf := make([]byte, maxEncChunkSize)
	var chunkIndex uint32
	lenBuf := make([]byte, 4)

	for {
		// Read chunk length (4 bytes)
		if _, err := io.ReadFull(inFile, lenBuf); err != nil {
			return fmt.Errorf("encryptor: read chunk length: %w", err)
		}
		encLen := binary.BigEndian.Uint32(lenBuf)

		// Terminator check
		if encLen == 0 {
			break
		}

		if encLen > maxEncChunkSize {
			return fmt.Errorf("encryptor: chunk size %d exceeds maximum %d", encLen, maxEncChunkSize)
		}

		// Read encrypted chunk
		if _, err := io.ReadFull(inFile, encBuf[:encLen]); err != nil {
			return fmt.Errorf("encryptor: read encrypted chunk: %w", err)
		}

		// Derive per-chunk nonce
		nonce := deriveChunkNonce(baseNonce, chunkIndex)

		// Decrypt chunk
		plaintext, err := gcm.Open(nil, nonce, encBuf[:encLen], nil)
		if err != nil {
			return fmt.Errorf("encryptor: decrypt chunk %d: %w", chunkIndex, err)
		}

		// Write decrypted plaintext
		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("encryptor: write decrypted chunk: %w", err)
		}

		chunkIndex++
	}

	return nil
}

// deriveChunkNonce creates a per-chunk nonce by XORing the base nonce's last 4 bytes with the chunk index.
//
// This ensures each chunk is encrypted with a unique nonce derived deterministically
// from the base nonce and chunk position, preventing nonce reuse across chunks.
func deriveChunkNonce(baseNonce []byte, chunkIndex uint32) []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce, baseNonce)

	// XOR last 4 bytes with big-endian chunk index
	idxBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBuf, chunkIndex)
	nonce[8] ^= idxBuf[0]
	nonce[9] ^= idxBuf[1]
	nonce[10] ^= idxBuf[2]
	nonce[11] ^= idxBuf[3]

	return nonce
}

package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	mode3 "github.com/cloudflare/circl/sign/dilithium/mode3"

	qscrypto "github.com/Odysse4s/QS-Sealer/internal/crypto"
	"github.com/Odysse4s/QS-Sealer/internal/encryptor"
	"github.com/Odysse4s/QS-Sealer/internal/hasher"
	"github.com/Odysse4s/QS-Sealer/internal/manifest"
)

// sealCmd seals a file by hashing, signing, and optionally encrypting it.
//
// The command produces a tamper-evident JSON manifest that records the file's
// SHA3-512 hash, Dilithium signature, metadata, and (if encrypted) the
// encrypted file path and algorithm used.
var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal an evidence file with a quantum-safe signature and optional encryption",
	Long: `Seal a file by computing its SHA3-512 hash, signing the hash payload with a
Dilithium Mode 3 (ML-DSA) private key, and writing a JSON manifest that
records all sealing metadata.

When --encrypt is set, the file is additionally encrypted using ML-KEM-768
key encapsulation with AES-256-GCM symmetric encryption. The encrypted file
is written alongside the original with a .qsenc extension.

The resulting manifest contains:
  • File metadata (name, path, size, timestamp)
  • SHA3-512 hash of the original file
  • Dilithium digital signature
  • Public key fingerprint
  • Encryption details (if applicable)`,
	Example: `  # Seal a file with a signing key
  qs-sealer seal --file evidence.zip --key qs-sealer.priv.pem

  # Seal and encrypt a file
  qs-sealer seal --file evidence.zip --key qs-sealer.priv.pem \
    --encrypt --enc-key qs-sealer.enc.pub.pem --output sealed.json`,
	RunE: runSeal,
}

func init() {
	sealCmd.Flags().StringP("file", "f", "", "Path to the evidence file to seal (required)")
	sealCmd.Flags().StringP("key", "k", "", "Path to the Dilithium private key PEM file (required)")
	sealCmd.Flags().StringP("output", "o", "manifest.json", "Output path for the JSON manifest")
	sealCmd.Flags().Bool("encrypt", false, "Encrypt the evidence file with ML-KEM-768 + AES-256-GCM")
	sealCmd.Flags().String("enc-key", "", "Path to the ML-KEM public key PEM file (required if --encrypt)")
	sealCmd.Flags().Bool("overwrite", false, "Overwrite output files if they already exist")

	_ = sealCmd.MarkFlagRequired("file")
	_ = sealCmd.MarkFlagRequired("key")
}

// runSeal is the main execution function for the seal command.
// It orchestrates hashing, signing, optional encryption, manifest creation,
// and user-facing output.
func runSeal(cmd *cobra.Command, args []string) error {
	// ── Read flags ──────────────────────────────────────────────────────────
	filePath, err := cmd.Flags().GetString("file")
	if err != nil {
		return fmt.Errorf("failed to read --file flag: %w", err)
	}

	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("failed to read --key flag: %w", err)
	}

	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("failed to read --output flag: %w", err)
	}

	encryptFlag, err := cmd.Flags().GetBool("encrypt")
	if err != nil {
		return fmt.Errorf("failed to read --encrypt flag: %w", err)
	}

	encKeyPath, err := cmd.Flags().GetString("enc-key")
	if err != nil {
		return fmt.Errorf("failed to read --enc-key flag: %w", err)
	}

	overwriteFlag, err := cmd.Flags().GetBool("overwrite")
	if err != nil {
		return fmt.Errorf("failed to read --overwrite flag: %w", err)
	}

	// ── Validate output paths ──────────────────────────────────────────────
	if !overwriteFlag {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("output file %q already exists; use --overwrite to overwrite", outputPath)
		}
		if encryptFlag {
			encFilePath := filePath + ".qsenc"
			if _, err := os.Stat(encFilePath); err == nil {
				return fmt.Errorf("encrypted output file %q already exists; use --overwrite to overwrite", encFilePath)
			}
		}
	}

	// ── Validate encryption flags ──────────────────────────────────────────
	if encryptFlag && encKeyPath == "" {
		return fmt.Errorf("--enc-key is required when --encrypt is set")
	}

	// ── Load Dilithium private key ─────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "🔑 Loading Dilithium private key from %s...\n", keyPath)
	privKey, err := qscrypto.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key from %q: %w", keyPath, err)
	}

	// Extract the public key for key ID computation.
	cryptoPubKey := privKey.Public()
	pubKey := cryptoPubKey.(*mode3.PublicKey)
	keyID := qscrypto.PublicKeyID(pubKey)

	// ── Gather file metadata ───────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "📄 Processing file: %s\n", filePath)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file %q: %w", filePath, err)
	}
	fileSize := fileInfo.Size()
	basename := filepath.Base(filePath)

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %q: %w", filePath, err)
	}

	// ── Hash the file ──────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "🔒 Computing SHA3-512 hash...\n")
	hash, err := hasher.HashFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to hash file %q: %w", filePath, err)
	}
	hashHex := hex.EncodeToString(hash)
	fmt.Fprintf(os.Stderr, "   Hash: %s\n", hashHex)

	// ── Build and sign the payload ─────────────────────────────────────────
	timestamp := time.Now().UTC().Format(time.RFC3339)

	fmt.Fprintf(os.Stderr, "✍️  Building signing payload...\n")
	payload, err := qscrypto.BuildSigningPayload(hash, fileSize, basename, timestamp)
	if err != nil {
		return fmt.Errorf("failed to build signing payload: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✍️  Signing with Dilithium Mode 3...\n")
	signature, err := qscrypto.SignPayload(payload, privKey)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	// ── Optional encryption ────────────────────────────────────────────────
	encFilePath := ""
	if encryptFlag {
		fmt.Fprintf(os.Stderr, "\n🔐 Encrypting file with ML-KEM-768 + AES-256-GCM...\n")

		kemPubKey, err := encryptor.LoadEncPublicKeyPEM(encKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load ML-KEM public key from %q: %w", encKeyPath, err)
		}

		ciphertext, sharedSecret, err := encryptor.Encapsulate(kemPubKey)
		if err != nil {
			return fmt.Errorf("failed to encapsulate shared secret: %w", err)
		}

		encFilePath = filePath + ".qsenc"
		if err := encryptor.EncryptFile(filePath, encFilePath, sharedSecret, ciphertext); err != nil {
			return fmt.Errorf("failed to encrypt file: %w", err)
		}

		fmt.Fprintf(os.Stderr, "   ✅ Encrypted file: %s\n", encFilePath)
	}

	// ── Build manifest ─────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "📝 Building manifest...\n")
	m := &manifest.Manifest{
		Version:       "1.0",
		Filename:      basename,
		FilePath:      absPath,
		FileSizeBytes: fileSize,
		Timestamp:     timestamp,
		Algorithm:     "DILITHIUM-MODE3-SHA3-512",
		SHA3Hash:      hashHex,
		Signature:     base64.StdEncoding.EncodeToString(signature),
		PublicKeyID:   keyID,
		Encrypted:     encryptFlag,
	}

	if encryptFlag {
		m.EncAlgorithm = "MLKEM768-AES256GCM"
		m.EncFile = encFilePath
	}

	// ── Save manifest ──────────────────────────────────────────────────────
	if err := manifest.Save(m, outputPath); err != nil {
		return fmt.Errorf("failed to save manifest to %q: %w", outputPath, err)
	}

	// ── Print summary ──────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n══════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, " ✅ Evidence sealed successfully!\n")
	fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, " 📄 File:       %s\n", basename)
	fmt.Fprintf(os.Stderr, " 📏 Size:       %d bytes\n", fileSize)
	fmt.Fprintf(os.Stderr, " 🕐 Timestamp:  %s\n", timestamp)
	fmt.Fprintf(os.Stderr, " 🔑 Key ID:     %s\n", keyID)
	fmt.Fprintf(os.Stderr, " 📝 Manifest:   %s\n", outputPath)
	if encryptFlag {
		fmt.Fprintf(os.Stderr, " 🔐 Encrypted:  %s\n", encFilePath)
	}
	fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")

	return nil
}

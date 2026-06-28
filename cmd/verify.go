package cmd

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	qscrypto "github.com/Odysse4s/QS-Sealer/internal/crypto"
	"github.com/Odysse4s/QS-Sealer/internal/encryptor"
	"github.com/Odysse4s/QS-Sealer/internal/hasher"
	"github.com/Odysse4s/QS-Sealer/internal/manifest"
)

// verifyCmd verifies a sealed evidence file against its manifest.
//
// It re-computes the file hash, compares it to the manifest in constant time,
// rebuilds the signing payload, and verifies the Dilithium signature. When
// --decrypt is set, it first decrypts the .qsenc file using the ML-KEM
// private key before performing verification.
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a sealed evidence file against its manifest",
	Long: `Verify the integrity and authenticity of a sealed evidence file.

This command performs two independent checks:

  1. Hash verification  — Re-computes the SHA3-512 hash of the file and
                          compares it (constant-time) to the hash recorded
                          in the manifest.
  2. Signature check    — Rebuilds the signing payload and verifies the
                          Dilithium Mode 3 digital signature using the
                          provided public key.

When --decrypt is set, the command first decrypts the .qsenc encrypted file
using the ML-KEM private key, then verifies the decrypted output.

Both checks must pass for verification to succeed. The command exits with
code 0 on success and code 1 on failure.`,
	Example: `  # Verify a sealed file
  qs-sealer verify --file evidence.zip --manifest manifest.json \
    --key qs-sealer.pub.pem

  # Decrypt and verify an encrypted sealed file
  qs-sealer verify --file evidence.zip.qsenc --manifest manifest.json \
    --key qs-sealer.pub.pem --decrypt \
    --enc-key qs-sealer.enc.priv.pem --output evidence-decrypted.zip`,
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringP("file", "f", "", "Path to the evidence file (or .qsenc file) to verify (required)")
	verifyCmd.Flags().StringP("manifest", "m", "", "Path to the JSON manifest file (required)")
	verifyCmd.Flags().StringP("key", "k", "", "Path to the Dilithium public key PEM file (required)")
	verifyCmd.Flags().Bool("decrypt", false, "Decrypt a .qsenc file before verification")
	verifyCmd.Flags().String("enc-key", "", "Path to the ML-KEM private key PEM file (required if --decrypt)")
	verifyCmd.Flags().StringP("output", "o", "", "Output path for the decrypted file (required if --decrypt)")

	_ = verifyCmd.MarkFlagRequired("file")
	_ = verifyCmd.MarkFlagRequired("manifest")
	_ = verifyCmd.MarkFlagRequired("key")
}

// runVerify is the main execution function for the verify command.
// It orchestrates optional decryption, hash comparison, signature verification,
// and user-facing result output.
func runVerify(cmd *cobra.Command, args []string) error {
	// ── Read flags ──────────────────────────────────────────────────────────
	filePath, err := cmd.Flags().GetString("file")
	if err != nil {
		return fmt.Errorf("failed to read --file flag: %w", err)
	}

	manifestPath, err := cmd.Flags().GetString("manifest")
	if err != nil {
		return fmt.Errorf("failed to read --manifest flag: %w", err)
	}

	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("failed to read --key flag: %w", err)
	}

	decryptFlag, err := cmd.Flags().GetBool("decrypt")
	if err != nil {
		return fmt.Errorf("failed to read --decrypt flag: %w", err)
	}

	encKeyPath, err := cmd.Flags().GetString("enc-key")
	if err != nil {
		return fmt.Errorf("failed to read --enc-key flag: %w", err)
	}

	outputFilePath, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("failed to read --output flag: %w", err)
	}

	// ── Validate decryption flags ──────────────────────────────────────────
	if decryptFlag {
		if encKeyPath == "" {
			return fmt.Errorf("--enc-key is required when --decrypt is set")
		}
		if outputFilePath == "" {
			return fmt.Errorf("--output is required when --decrypt is set")
		}
	}

	// ── Load manifest ──────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "📝 Loading manifest from %s...\n", manifestPath)
	m, err := manifest.Load(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to load manifest from %q: %w", manifestPath, err)
	}

	// ── Optional decryption ────────────────────────────────────────────────
	if decryptFlag {
		fmt.Fprintf(os.Stderr, "🔓 Decrypting %s...\n", filePath)

		kemPrivKey, err := encryptor.LoadEncPrivateKeyPEM(encKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load ML-KEM private key from %q: %w", encKeyPath, err)
		}

		if err := encryptor.DecryptFile(filePath, outputFilePath, kemPrivKey); err != nil {
			return fmt.Errorf("failed to decrypt file %q: %w", filePath, err)
		}

		fmt.Fprintf(os.Stderr, "   ✅ Decrypted to: %s\n", outputFilePath)

		// Verify against the decrypted file from here on.
		filePath = outputFilePath
	}

	// ── Load Dilithium public key ──────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "🔑 Loading Dilithium public key from %s...\n", keyPath)
	pubKey, err := qscrypto.LoadPublicKeyPEM(keyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key from %q: %w", keyPath, err)
	}

	keyID := qscrypto.PublicKeyID(pubKey)
	if keyID != m.PublicKeyID {
		fmt.Fprintf(os.Stderr, " ⚠️  WARNING: Loaded public key ID (%s) does not match manifest key ID (%s)!\n", keyID, m.PublicKeyID)
	}

	// ── Cross-check file size ──────────────────────────────────────────────
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file %q: %w", filePath, err)
	}
	if fileInfo.Size() != m.FileSizeBytes {
		fmt.Fprintf(os.Stderr, " ❌ File size mismatch: manifest says %d bytes, actual is %d bytes\n", m.FileSizeBytes, fileInfo.Size())
		return fmt.Errorf("file size mismatch: expected %d, got %d", m.FileSizeBytes, fileInfo.Size())
	}

	// ── Recompute file hash ────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "🔒 Computing SHA3-512 hash of %s...\n", filePath)
	recomputedHash, err := hasher.HashFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to hash file %q: %w", filePath, err)
	}
	recomputedHashHex := hex.EncodeToString(recomputedHash)

	// ── Compare hashes (constant-time) ─────────────────────────────────────
	manifestHashBytes, err := hex.DecodeString(m.SHA3Hash)
	if err != nil {
		return fmt.Errorf("failed to decode manifest hash (invalid hex): %w", err)
	}

	hashMatch := subtle.ConstantTimeCompare(recomputedHash, manifestHashBytes) == 1

	// ── Rebuild signing payload and verify signature ───────────────────────
	fmt.Fprintf(os.Stderr, "✍️  Verifying Dilithium signature...\n")
	payload, err := qscrypto.BuildSigningPayload(recomputedHash, m.FileSizeBytes, m.Filename, m.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to rebuild signing payload: %w", err)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode manifest signature (invalid base64): %w", err)
	}

	sigValid := qscrypto.VerifyPayload(payload, signatureBytes, pubKey)

	// ── Report results ─────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n══════════════════════════════════════════════\n")

	if hashMatch && sigValid {
		fmt.Fprintf(os.Stderr, " ✅ VERIFICATION PASSED\n")
		fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")
		fmt.Fprintf(os.Stderr, " 📄 File:       %s\n", m.Filename)
		fmt.Fprintf(os.Stderr, " 🔒 Hash:       %s\n", recomputedHashHex)
		fmt.Fprintf(os.Stderr, " ✍️  Signature:  VALID\n")
		fmt.Fprintf(os.Stderr, " 🔑 Key ID:     %s\n", m.PublicKeyID)
		fmt.Fprintf(os.Stderr, " 🕐 Sealed at:  %s\n", m.Timestamp)
		if decryptFlag {
			fmt.Fprintf(os.Stderr, " 🔓 Decrypted:  %s\n", outputFilePath)
		}
		fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")
		return nil
	}

	// At least one check failed.
	fmt.Fprintf(os.Stderr, " ❌ VERIFICATION FAILED\n")
	fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")

	if !hashMatch {
		fmt.Fprintf(os.Stderr, " ❌ Hash mismatch!\n")
		fmt.Fprintf(os.Stderr, "    Expected: %s\n", m.SHA3Hash)
		fmt.Fprintf(os.Stderr, "    Got:      %s\n", recomputedHashHex)
	} else {
		fmt.Fprintf(os.Stderr, " ✅ Hash:       OK\n")
	}

	if !sigValid {
		fmt.Fprintf(os.Stderr, " ❌ Signature:  INVALID\n")
	} else {
		fmt.Fprintf(os.Stderr, " ✅ Signature:  VALID\n")
	}

	fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, "\n⚠️  The evidence file may have been tampered with!\n")

	return fmt.Errorf("the evidence file has been tampered with")
}

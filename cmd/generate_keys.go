package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	qscrypto "github.com/Odysse4s/QS-Sealer/internal/crypto"
	"github.com/Odysse4s/QS-Sealer/internal/encryptor"
)

// generateKeysCmd generates post-quantum cryptographic keypairs.
//
// By default it produces a Dilithium Mode 3 (ML-DSA) signing keypair.
// When the --encryption flag is set it additionally generates an ML-KEM-768
// key encapsulation keypair for hybrid encryption workflows.
var generateKeysCmd = &cobra.Command{
	Use:   "generate-keys",
	Short: "Generate quantum-safe signing (and optional encryption) keypairs",
	Long: `Generate a post-quantum Dilithium Mode 3 (ML-DSA / FIPS 204) signing keypair.

The generated keys are saved as PEM-encoded files in the specified output
directory. When --encryption is set, an additional ML-KEM-768 (FIPS 203)
key encapsulation keypair is generated for file encryption workflows.

Output files:
  qs-sealer.pub.pem       — Dilithium public key  (used for verify)
  qs-sealer.priv.pem      — Dilithium private key  (used for seal)
  qs-sealer.enc.pub.pem   — ML-KEM public key      (used for seal --encrypt)
  qs-sealer.enc.priv.pem  — ML-KEM private key      (used for verify --decrypt)`,
	Example: `  # Generate signing keys in the current directory
  qs-sealer generate-keys

  # Generate signing + encryption keys in a custom directory
  qs-sealer generate-keys --output-dir ./keys --encryption`,
	RunE: runGenerateKeys,
}

func init() {
	generateKeysCmd.Flags().StringP("output-dir", "o", ".", "Directory to write key files to")
	generateKeysCmd.Flags().BoolP("encryption", "e", false, "Also generate ML-KEM-768 encryption keypair")
}

// runGenerateKeys is the main execution function for the generate-keys command.
// It creates output directories, generates keypairs, saves PEM files, and
// prints a summary of generated artifacts to the terminal.
func runGenerateKeys(cmd *cobra.Command, args []string) error {
	outputDir, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return fmt.Errorf("failed to read --output-dir flag: %w", err)
	}

	encryptionFlag, err := cmd.Flags().GetBool("encryption")
	if err != nil {
		return fmt.Errorf("failed to read --encryption flag: %w", err)
	}

	// Ensure the output directory exists.
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory %q: %w", outputDir, err)
	}

	// ── Dilithium (ML-DSA) Signing Keypair ─────────────────────────────────
	fmt.Fprintf(os.Stderr, "🔑 Generating Dilithium Mode 3 (ML-DSA) signing keypair...\n")

	pubKey, privKey, err := qscrypto.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate Dilithium keypair: %w", err)
	}

	pubKeyPath := filepath.Join(outputDir, "qs-sealer.pub.pem")
	privKeyPath := filepath.Join(outputDir, "qs-sealer.priv.pem")

	if err := qscrypto.SavePublicKeyPEM(pubKey, pubKeyPath); err != nil {
		return fmt.Errorf("failed to save public key to %q: %w", pubKeyPath, err)
	}

	if err := qscrypto.SavePrivateKeyPEM(privKey, privKeyPath); err != nil {
		return fmt.Errorf("failed to save private key to %q: %w", privKeyPath, err)
	}

	keyID := qscrypto.PublicKeyID(pubKey)
	fmt.Fprintf(os.Stderr, "   ✅ Public key:   %s\n", pubKeyPath)
	fmt.Fprintf(os.Stderr, "   ✅ Private key:  %s\n", privKeyPath)
	fmt.Fprintf(os.Stderr, "   🆔 Key ID:       %s\n", keyID)

	// ── ML-KEM-768 Encryption Keypair (optional) ───────────────────────────
	if encryptionFlag {
		fmt.Fprintf(os.Stderr, "\n🔐 Generating ML-KEM-768 encryption keypair...\n")

		encPubKey, encPrivKey, err := encryptor.GenerateEncryptionKeypair()
		if err != nil {
			return fmt.Errorf("failed to generate ML-KEM keypair: %w", err)
		}

		encPubKeyPath := filepath.Join(outputDir, "qs-sealer.enc.pub.pem")
		encPrivKeyPath := filepath.Join(outputDir, "qs-sealer.enc.priv.pem")

		if err := encryptor.SaveEncPublicKeyPEM(encPubKey, encPubKeyPath); err != nil {
			return fmt.Errorf("failed to save encryption public key to %q: %w", encPubKeyPath, err)
		}

		if err := encryptor.SaveEncPrivateKeyPEM(encPrivKey, encPrivKeyPath); err != nil {
			return fmt.Errorf("failed to save encryption private key to %q: %w", encPrivKeyPath, err)
		}

		fmt.Fprintf(os.Stderr, "   ✅ Encryption public key:  %s\n", encPubKeyPath)
		fmt.Fprintf(os.Stderr, "   ✅ Encryption private key: %s\n", encPrivKeyPath)
	}

	// ── Summary ────────────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n══════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, " ✅ Key generation complete!\n")
	fmt.Fprintf(os.Stderr, " 📂 Output directory: %s\n", outputDir)
	fmt.Fprintf(os.Stderr, " 🔑 Signing algorithm: DILITHIUM-MODE3 (FIPS 204)\n")
	if encryptionFlag {
		fmt.Fprintf(os.Stderr, " 🔐 Encryption algorithm: ML-KEM-768 (FIPS 203)\n")
	}
	fmt.Fprintf(os.Stderr, "══════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, "\n⚠️  Keep your private key(s) secure! Never share them.\n")

	return nil
}

// Package cmd implements all CLI commands for the QS-Sealer application.
//
// QS-Sealer is a post-quantum cryptographic tool for sealing digital evidence
// with FIPS 204 (ML-DSA/Dilithium) signatures and optional FIPS 203 (ML-KEM)
// encryption. This package wires together the internal crypto, hasher, manifest,
// and encryptor packages into a cohesive command-line interface built on cobra.
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the top-level cobra command for qs-sealer.
// All subcommands (generate-keys, seal, verify) are registered as children.
var rootCmd = &cobra.Command{
	Use:   "qs-sealer",
	Short: "Quantum-Safe Evidence Sealer",
	Long: `QS-Sealer is a post-quantum cryptographic tool for sealing digital evidence
with FIPS 204 (ML-DSA/Dilithium) signatures and optional FIPS 203 (ML-KEM) encryption.

It provides three core workflows:

  1. generate-keys  — Generate ML-DSA (Dilithium) signing keypairs and
                      optionally ML-KEM encryption keypairs.
  2. seal           — Hash, sign, and optionally encrypt a file, producing
                      a tamper-evident JSON manifest.
  3. verify         — Re-hash, verify the signature, and optionally decrypt
                      a sealed evidence file against its manifest.

All cryptographic operations use post-quantum algorithms recommended by NIST:
  • ML-DSA / Dilithium Mode 3 (FIPS 204) for digital signatures
  • ML-KEM-768 (FIPS 203) for key encapsulation / encryption`,
	Version: "1.0.0",
}

// Execute runs the root command and exits with code 1 on error.
// This is the main entry point called from main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(generateKeysCmd)
	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(verifyCmd)
}

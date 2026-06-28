# QS-Sealer — Quantum-Safe Evidence Sealer

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA%20%2F%20Dilithium-blue)](https://csrc.nist.gov/pubs/fips/204/final)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-blue)](https://csrc.nist.gov/pubs/fips/203/final)

A post-quantum cryptographic CLI tool for sealing digital evidence with **FIPS 204 (ML-DSA / Dilithium Mode 3)** signatures, **SHA3-512** hashing, and optional **FIPS 203 (ML-KEM-768)** hybrid encryption.

Designed for forensic chain-of-custody workflows — hash, sign, and optionally encrypt arbitrarily large files (RAM dumps, disk images) with **O(1) memory complexity**.

---

## Features

| Feature | Standard | Security Level |
|---|---|---|
| **Digital Signatures** | ML-DSA / Dilithium Mode 3 (FIPS 204) | 128-bit post-quantum |
| **File Hashing** | SHA3-512 | 256-bit post-quantum |
| **Key Encapsulation** | ML-KEM-768 (FIPS 203) | 192-bit post-quantum |
| **Symmetric Encryption** | AES-256-GCM (chunked) | 256-bit classical |

### Security Hardening

- **Context-bound signatures** — Signature binds `hash ‖ size ‖ filename ‖ timestamp`, preventing detachment attacks
- **O(1) streaming hash** — 4MB `io.CopyBuffer` for optimal NVMe throughput on 64GB+ files
- **Chunked AES-GCM** — 1MB chunks with per-chunk authentication tags; tamper detected per-chunk
- **Deterministic nonce derivation** — `base_nonce ⊕ chunk_index` prevents nonce reuse without random I/O
- **Constant-time hash comparison** — Uses `crypto/subtle.ConstantTimeCompare` during verification
- **Private key protection** — PEM files written with `0600` permissions

---

## Installation

```bash
# Requires Go 1.21+
git clone https://github.com/Odysse4s/QS-Sealer.git
cd QS-Sealer
go build -o qs-sealer .

# Check version
qs-sealer --version
```

---

## Usage

### 1. Generate Keys

```bash
# Generate Dilithium signing keypair
qs-sealer generate-keys --output-dir ./keys

# Generate signing + encryption keypairs
qs-sealer generate-keys --output-dir ./keys --encryption
```

Output:
```
qs-sealer.pub.pem        — Dilithium public key (for verification)
qs-sealer.priv.pem       — Dilithium private key (for sealing)
qs-sealer.enc.pub.pem    — ML-KEM public key (for encryption)
qs-sealer.enc.priv.pem   — ML-KEM private key (for decryption)
```

### 2. Seal Evidence

```bash
# Seal a file (hash + sign)
qs-sealer seal --file evidence.raw --key ./keys/qs-sealer.priv.pem

# Seal + encrypt
qs-sealer seal --file evidence.raw --key ./keys/qs-sealer.priv.pem \
  --encrypt --enc-key ./keys/qs-sealer.enc.pub.pem \
  --output evidence-manifest.json

# Overwrite an existing manifest
qs-sealer seal --file evidence.raw --key ./keys/qs-sealer.priv.pem \
  --output manifest.json --overwrite
```

Produces a `manifest.json`:
```json
{
  "version": "1.0",
  "filename": "evidence.raw",
  "filepath": "/path/to/evidence.raw",
  "file_size_bytes": 68719476736,
  "timestamp": "2026-06-26T18:00:00Z",
  "algorithm": "DILITHIUM-MODE3-SHA3-512",
  "sha3_512_hash": "a7ffc6f8bf1ed76651...",
  "signature": "MEUCIQDx...",
  "public_key_id": "3b4c5d6e...",
  "encrypted": true,
  "enc_algorithm": "MLKEM768-AES256GCM",
  "encrypted_file": "evidence.raw.qsenc"
}
```

### 3. Verify Evidence

```bash
# Verify a sealed file
qs-sealer verify --file evidence.raw --manifest manifest.json \
  --key ./keys/qs-sealer.pub.pem

# Decrypt + verify an encrypted file
qs-sealer verify --file evidence.raw.qsenc --manifest manifest.json \
  --key ./keys/qs-sealer.pub.pem \
  --decrypt --enc-key ./keys/qs-sealer.enc.priv.pem \
  --output evidence-decrypted.raw
```

---

## Architecture

```
QS-Sealer/
├── main.go                        # Entry point
├── cmd/
│   ├── root.go                    # Cobra root command
│   ├── generate_keys.go           # generate-keys subcommand
│   ├── seal.go                    # seal subcommand
│   └── verify.go                  # verify subcommand
├── internal/
│   ├── crypto/
│   │   ├── keys.go                # Dilithium key management + PEM I/O
│   │   ├── signer.go              # Context-bound payload construction + signing
│   │   └── verifier.go            # Signature verification
│   ├── encryptor/
│   │   ├── kem.go                 # ML-KEM-768 key encapsulation
│   │   └── stream.go              # Chunked AES-256-GCM streaming
│   ├── hasher/
│   │   └── sha3.go                # Streaming SHA3-512 (4MB buffer)
│   └── manifest/
│       └── manifest.go            # JSON manifest schema + I/O
└── README.md
```

### Encrypted File Format (`.qsenc`)

```
┌──────────────────────────────────────┐
│ Magic: "QSSEAL01" (8 bytes)         │
│ Version: 0x01    (1 byte)           │
│ Chunk Size: uint32 BE (4 bytes)     │
│ KEM Ciphertext (1088 bytes)         │
│ Base Nonce (12 bytes)               │
├──────────────────────────────────────┤
│ Chunk 0: [len][ciphertext+GCM tag]  │
│ Chunk 1: [len][ciphertext+GCM tag]  │
│ ...                                 │
│ Terminator: 4 zero bytes            │
└──────────────────────────────────────┘
```

---

## Dependencies

| Package | Purpose |
|---|---|
| [`github.com/cloudflare/circl`](https://github.com/cloudflare/circl) | Dilithium Mode 3 (ML-DSA) + ML-KEM-768 |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) | SHA3-512 / SHA3-256 hashing |
| [`github.com/spf13/cobra`](https://github.com/spf13/cobra) | CLI framework |

---

## License

MIT

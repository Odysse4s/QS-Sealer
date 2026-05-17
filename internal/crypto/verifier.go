package crypto

import (
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// VerifyPayload verifies a Dilithium signature against a 64-byte payload and public key.
//
// Returns true if the signature is valid for the given payload under the
// provided public key, false otherwise. This function does not return an error;
// any invalid input (wrong sizes, corrupted data) simply returns false.
func VerifyPayload(payload []byte, signature []byte, pubKey *mode3.PublicKey) bool {
	return mode3.Verify(pubKey, payload, signature)
}

// Package wire speaks the bytes the manager expects: authd enrollment, the
// AES-CMAC request signature, and the HTTPS and Unix-socket transports. It
// knows nothing about scenarios (see docu/04-wire-protocol.md).
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// AESCMAC computes the AES-CMAC (RFC 4493) of msg under key, which must be a
// valid AES key (16, 24 or 32 bytes). This is the manager's request signature;
// the canonical byte sequence it is computed over is assembled in sign.go.
//
// Implemented here rather than pulled from a dependency because Go's standard
// library has no CMAC and the algorithm is small and worth owning outright.
// cmac_test.go pins it against the RFC 4493 vectors AND against a fixed
// canonical-string vector, so a regression is caught with no manager running.
func AESCMAC(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	bs := block.BlockSize()

	k1, k2 := subkeys(block, bs)

	// The final block is the last full block XOR K1 when the message is a
	// non-empty multiple of the block size, otherwise the padded remainder
	// XOR K2. Everything before that final block is plain CBC-MAC.
	complete := len(msg) > 0 && len(msg)%bs == 0
	lastLen := bs
	if !complete {
		lastLen = len(msg) % bs // 0 for the empty message
	}
	prefix := len(msg) - lastLen

	var lastBlock []byte
	if complete {
		lastBlock = xor(msg[prefix:], k1)
	} else {
		lastBlock = xor(pad(msg[prefix:], bs), k2)
	}

	mac := make([]byte, bs)
	for i := 0; i < prefix; i += bs {
		xorInto(mac, msg[i:i+bs])
		block.Encrypt(mac, mac)
	}
	xorInto(mac, lastBlock)
	block.Encrypt(mac, mac)
	return mac, nil
}

// subkeys derives K1 and K2 from L = AES(K, 0^128), per RFC 4493 §2.3.
func subkeys(block cipher.Block, bs int) (k1, k2 []byte) {
	const rb = 0x87 // the constant for the 128-bit block

	l := make([]byte, bs)
	block.Encrypt(l, l) // L = AES(K, 0...0)

	k1 = shiftLeft(l)
	if l[0]&0x80 != 0 {
		k1[bs-1] ^= rb
	}
	k2 = shiftLeft(k1)
	if k1[0]&0x80 != 0 {
		k2[bs-1] ^= rb
	}
	return k1, k2
}

func shiftLeft(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	return out
}

// pad applies the 10* padding of RFC 4493 to a partial final block.
func pad(last []byte, bs int) []byte {
	out := make([]byte, bs)
	copy(out, last)
	out[len(last)] = 0x80
	return out
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// constantTimeEqual reports whether a and b are equal, without leaking timing.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

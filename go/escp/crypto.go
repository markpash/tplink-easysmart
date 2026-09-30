package escp

import (
	"crypto/rand"
	"math/big"
)

// staticRC4 is the legacy transport cipher: RC4 (PRGA only) over a fixed,
// pre-keyed 256-byte S-box. The table is cloned per call, matching of.Code().
func staticRC4(in []byte) []byte {
	s := staticSBox
	out := make([]byte, len(in))
	var i, j byte
	for k := 0; k < len(in); k++ {
		i++
		j += s[i]
		s[i], s[j] = s[j], s[i]
		out[k] = in[k] ^ s[s[i]+s[j]]
	}
	return out
}

// sessionRC4 is the 8-byte-state RC4 used after the RSA session-key exchange
// (of.V). It is intentionally tiny; the switch and utility both use it.
func sessionRC4(in []byte, key string) []byte {
	const n = 8
	var s [n]byte
	for i := 0; i < n; i++ {
		s[i] = byte(i)
	}
	kb := []byte(key)
	var j byte
	for i := 0; i < n; i++ {
		j = (j + s[i] + kb[i%len(kb)]) % n
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(in))
	var i, jj byte
	for k := 0; k < len(in); k++ {
		i = (i + 1) % n
		jj = (jj + s[i]) % n
		s[i], s[jj] = s[jj], s[i]
		out[k] = in[k] ^ s[(s[i]+s[jj])%n]
	}
	return out
}

const sessionKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// newSessionKey generates an 8-character alphanumeric key (same shape as the
// utility's util.mine(8) SecureRandom key).
func newSessionKey() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = sessionKeyAlphabet[int(b[i])%len(sessionKeyAlphabet)]
	}
	return string(b), nil
}

// rsaEncryptSessionKey implements transfer.I.I(): RSA public-key encryption of
// the session key with e=65537 and the given modulus.
//
//   - message integer m = little-endian interpretation of the key bytes
//   - c = m^e mod n
//   - output = [0x00][limbCount][c little-endian, limbCount*2 bytes]
func rsaEncryptSessionKey(key string, modulus []byte) []byte {
	n := new(big.Int).SetBytes(modulus)
	e := big.NewInt(65537)

	kb := []byte(key)
	le := make([]byte, len(kb))
	for i := range kb {
		le[i] = kb[len(kb)-1-i]
	}
	m := new(big.Int).SetBytes(le)
	c := new(big.Int).Exp(m, e, n)

	limbs := len(modulus) / 2
	out := make([]byte, 2+2*limbs)
	out[0] = 0x00
	out[1] = byte(limbs)
	cb := c.Bytes() // big-endian, minimal
	for i := 0; i < len(cb); i++ {
		pos := 2 + i
		if pos >= len(out) {
			break
		}
		out[pos] = cb[len(cb)-1-i] // write least-significant first
	}
	return out
}

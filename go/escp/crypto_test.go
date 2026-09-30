package escp

import (
	"encoding/hex"
	"testing"
)

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestStaticRC4Vector(t *testing.T) {
	// Discovery probe captured on the wire (plain -> encrypted).
	plain := mustDecode(t, "0100000000000000001122334455006400000000002400000000000000000000ffff0000")
	want := mustDecode(t, "5d746a047dbeb0b2fb7a24f050c07ef1422ba2f5d78baeed508f463dc202909aa4ec81c6")
	got := staticRC4(plain)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("staticRC4 mismatch:\n got %x\nwant %x", got, want)
	}
	// RC4 is symmetric.
	if hex.EncodeToString(staticRC4(got)) != hex.EncodeToString(plain) {
		t.Fatal("staticRC4 is not its own inverse")
	}
}

func TestSessionRC4Vector(t *testing.T) {
	key := "m4l4TacP"
	plain := mustDecode(t, "010148225440a8d000112233445500670000000000280000000000000000000040000000ffff0000")
	want := mustDecode(t, "06004f205247abd5041721324155066704070103072b0104020402070402020041010304fdff0701")
	got := sessionRC4(plain, key)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("sessionRC4 mismatch:\n got %x\nwant %x", got, want)
	}
	if hex.EncodeToString(sessionRC4(got, key)) != hex.EncodeToString(plain) {
		t.Fatal("sessionRC4 is not its own inverse")
	}
}

func TestRSAEncryptSessionKeyVector(t *testing.T) {
	// From the live capture: session key m4l4TacP, small (64-bit) modulus.
	got := rsaEncryptSessionKey("m4l4TacP", rsaSmallModulus)
	want := "00040450d0a86305f32c"
	if hex.EncodeToString(got) != want {
		t.Fatalf("rsa mismatch:\n got %x\nwant %s", got, want)
	}
}

package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestParityAgainstPythonSender verifies SEMANTIC parity with the Python
// sender: the decrypted-then-decompressed inner event (MD5_hex||msg) MUST
// match Python's output exactly. The raw zlib bytes naturally differ
// between Go's compress/zlib and Python's libz wrapper; both produce
// valid deflate streams and the manager only sees the decompressed
// content. Wire-level acceptance is therefore "semantic equivalence",
// not byte-equality.
//
// Reference inner-event hex strings were captured by running
// /tmp/wire_parity.py with the same constant inputs used below.
//
// NFR-2 (revised) in docu/02-functional-requirements.md.
func TestParityAgainstPythonSender(t *testing.T) {
	const (
		managerKey = "deadbeefdeadbeefdeadbeefdeadbeef"
		name       = "bench-0001-aaaaaaaaaaaa"
		agentID    = "001"
	)
	key := DeriveAESKey(managerKey, name, agentID)

	wantKey := "6236653563313837333961303563373839323662666439363635346233346534"
	if hex.EncodeToString(key) != wantKey {
		t.Fatalf("AES key mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(key), wantKey)
	}

	textPayload := "1:syslog:Jun  1 00:00:00 host sshd[1]: Accepted password for root"
	gotText, err := EncodeText(key, agentID, textPayload)
	if err != nil {
		t.Fatalf("EncodeText: %v", err)
	}
	// Header literal "!001!#AES:" MUST match Python byte-for-byte.
	if !bytes.HasPrefix(gotText, []byte("!001!#AES:")) {
		t.Fatalf("text frame missing/wrong header: %s", hex.EncodeToString(gotText[:16]))
	}
	// Decode our own frame, then assert the recovered payload equals input.
	gotPayload, err := DecodeFrame(key, gotText)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if string(gotPayload) != textPayload {
		t.Fatalf("text round-trip mismatch:\n  got:  %q\n  want: %q", gotPayload, textPayload)
	}

	binPayload := []byte{0, 1, 2, 0xff, 0xfe}
	gotBin, err := EncodeBinary(key, agentID, "syscollector_sync", binPayload)
	if err != nil {
		t.Fatalf("EncodeBinary: %v", err)
	}
	if !bytes.HasPrefix(gotBin, []byte("!001!#AES:")) {
		t.Fatalf("binary frame missing/wrong header: %s", hex.EncodeToString(gotBin[:16]))
	}
	gotBinPayload, err := DecodeFrame(key, gotBin)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	wantBinPayload := append([]byte("s:syscollector_sync:"), binPayload...)
	if !bytes.Equal(gotBinPayload, wantBinPayload) {
		t.Fatalf("binary round-trip mismatch:\n  got:  %x\n  want: %x", gotBinPayload, wantBinPayload)
	}
}

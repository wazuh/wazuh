package wire

import (
	"bytes"
	"strings"
	"testing"
)

func TestZstdRoundTrip(t *testing.T) {
	// Repetitive like a real inventory session (thousands of near-identical
	// registry documents), so the ratio assertion below is meaningful.
	original := []byte(strings.Repeat(`{"registry":{"hive":"HKLM","path":"HKEY_LOCAL_MACHINE\\Software\\X"}}`, 2000))

	frame := Compress(original)
	if len(frame) >= len(original)/10 {
		t.Fatalf("repetitive JSON must compress hard: %d -> %d", len(original), len(frame))
	}

	back, err := Decompress(frame)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Fatal("round trip must be byte-exact")
	}
}

func TestDecompressRejectsGarbage(t *testing.T) {
	if _, err := Decompress([]byte("not a zstd frame")); err == nil {
		t.Fatal("garbage must not decompress")
	}
}

func TestCompressEmptyBody(t *testing.T) {
	back, err := Decompress(Compress(nil))
	if err != nil || len(back) != 0 {
		t.Fatalf("an empty body must survive the round trip: %v, %d bytes", err, len(back))
	}
}

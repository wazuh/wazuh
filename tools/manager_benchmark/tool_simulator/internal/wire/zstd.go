package wire

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// zstd is used in two places with opposite directions: Compress produces the
// Content-Encoding: zstd request bodies remoted accepts on its authenticated
// routes (the CMAC then signs the COMPRESSED bytes -- they are the wire bytes),
// and Decompress reads the .json.zst captured-session dumps, which are stored
// compressed because the full-fidelity first-connect corpus would otherwise
// put ~44 MB of JSON in the repo.
//
// klauspost/compress is pure Go on purpose: the tool must cross-build and run
// from a plain `go build` (docu/11), which rules out a cgo binding to the
// repo's vendored C zstd.

var (
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
)

func init() {
	// EncodeAll/DecodeAll on shared, concurrency-safe instances: every use is
	// whole-buffer (a session body, a dump file), never streaming.
	var err error
	if zstdEncoder, err = zstd.NewWriter(nil); err != nil {
		panic(fmt.Sprintf("zstd encoder: %v", err))
	}
	if zstdDecoder, err = zstd.NewReader(nil); err != nil {
		panic(fmt.Sprintf("zstd decoder: %v", err))
	}
}

// Compress returns body as one zstd frame with the decompressed size declared
// in the frame header (EncodeAll pledges it), which lets the server size its
// buffers up front.
func Compress(body []byte) []byte {
	return zstdEncoder.EncodeAll(body, make([]byte, 0, len(body)/3))
}

// Decompress returns the decompressed content of one zstd frame.
func Decompress(frame []byte) ([]byte, error) {
	return zstdDecoder.DecodeAll(frame, nil)
}

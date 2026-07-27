package wire

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Fixed IV used by Wazuh remoted for AES-256-CBC frames. See
// docu/05-wire-protocol.md §3.
var IV = []byte("FEDCBA0987654321")

// Routing prefix common to every Wazuh agent message. Matches
// benchmark_sender.py _compose_event / _encode_binary.
//
//	msg = ROUTING_PREFIX + payload
var routingPrefix = []byte("55555" + "1234567891" + ":" + "5555" + ":")

const aesBlock = 16

// pkcs7Pad pads data with PKCS#7 to a multiple of blockSize. Matches
// PyCryptodome's Crypto.Util.Padding.pad default style — even fully aligned
// data gets a full block of padding appended.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	n := int(data[len(data)-1])
	if n <= 0 || n > aesBlock || n > len(data) {
		return data
	}
	return data[:len(data)-n]
}

// wazuhPad prepends '!' bytes to align the input to a multiple of 8 bytes.
// When the input is already aligned, 8 '!' bytes are prepended anyway —
// this quirk matches benchmark_sender.py _wazuh_pad.
func wazuhPad(data []byte) []byte {
	extra := len(data) % 8
	padCount := 8 - extra
	// When extra == 0, padCount stays at 8 — always at least 8 '!' bytes.
	return append(bytes.Repeat([]byte{'!'}, padCount), data...)
}

func aesEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext)%aesBlock != 0 {
		return nil, fmt.Errorf("wire: plaintext not aligned to %d (got %d)", aesBlock, len(plaintext))
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(plaintext))
	mode.CryptBlocks(ct, plaintext)
	return ct, nil
}

func aesDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aesBlock != 0 {
		return nil, fmt.Errorf("wire: ciphertext not aligned to %d (got %d)", aesBlock, len(ciphertext))
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	pt := make([]byte, len(ciphertext))
	mode.CryptBlocks(pt, ciphertext)
	return pt, nil
}

func zlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// composeEvent builds the inner event: MD5_hex(msg) || msg
// where msg = routingPrefix || payload. Matches _compose_event in
// benchmark_sender.py.
func composeEvent(payload []byte) []byte {
	msg := make([]byte, 0, len(routingPrefix)+len(payload))
	msg = append(msg, routingPrefix...)
	msg = append(msg, payload...)
	sum := md5.Sum(msg)
	out := make([]byte, 0, 32+len(msg))
	out = append(out, hex.EncodeToString(sum[:])...)
	out = append(out, msg...)
	return out
}

// EncodeBinary builds the inner identifier blob for an inventory_sync
// message: routingPrefix || "s:" || identifier || ":" || binary.
// Matches benchmark_sender.py _encode_binary.
func EncodeBinary(aesKey []byte, agentID, identifier string, binary []byte) ([]byte, error) {
	payload := make([]byte, 0, 2+len(identifier)+1+len(binary))
	payload = append(payload, 's', ':')
	payload = append(payload, identifier...)
	payload = append(payload, ':')
	payload = append(payload, binary...)
	return encodeFrame(aesKey, agentID, payload)
}

// EncodeText builds an inner blob for a plain text payload (control
// messages and engine events). Matches benchmark_sender.py _encode_text.
// The caller provides the raw payload (e.g. `1:<location>:<line>` for an
// engine event, or `#!-agent startup {...}` for a control msg).
func EncodeText(aesKey []byte, agentID, text string) ([]byte, error) {
	return encodeFrame(aesKey, agentID, []byte(text))
}

func encodeFrame(aesKey []byte, agentID string, payload []byte) ([]byte, error) {
	inner := composeEvent(payload)

	compressed, err := zlibCompress(inner)
	if err != nil {
		return nil, fmt.Errorf("zlib compress: %w", err)
	}
	padded := wazuhPad(compressed)
	aesPadded := pkcs7Pad(padded, aesBlock)

	encrypted, err := aesEncrypt(aesKey, IV, aesPadded)
	if err != nil {
		return nil, fmt.Errorf("aes encrypt: %w", err)
	}

	header := []byte(fmt.Sprintf("!%s!#AES:", agentID))
	frame := make([]byte, 0, len(header)+len(encrypted))
	frame = append(frame, header...)
	frame = append(frame, encrypted...)
	return frame, nil
}

// WriteFrame writes one length-prefixed frame to w. The length prefix is
// a 4-byte little-endian uint32. Matches benchmark_sender.py _send_frame.
func WriteFrame(w io.Writer, frame []byte) error {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(frame)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(frame); err != nil {
		return err
	}
	return nil
}

// ReadFrame reads one length-prefixed frame from r. It returns the full
// post-header bytes (i.e. everything after the 4-byte length prefix).
func ReadFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(hdr)
	if length == 0 || length > 64*1024*1024 {
		return nil, fmt.Errorf("wire: refusing frame of length %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// DecodeFrame reverses encodeFrame, returning the inner payload that was
// fed to EncodeBinary / EncodeText (i.e. WITHOUT the routing prefix or the
// MD5 header).
//
// Frame layout (post length-prefix):
//
//	"#AES:" || AES_CBC(pkcs7_pad(wazuh_pad(zlib(MD5_hex(msg) || msg))))
//	  where msg = <53-byte routing prefix> || payload
//
// For frames received from the manager the leading "!agentID!" header is
// absent (the manager uses just "#AES:" for the inbound direction). The
// manager's outbound `msg` keeps the same overall layout but the routing
// prefix BYTES may differ from the agent's literal "55555…5555:" — we
// therefore strip 53 bytes blindly instead of validating, matching
// benchmark_sender.py _decode_frame (colon2 = 32 + 5 + 10 + 1 + 4 = 52,
// then +1 for the trailing ':' makes 53).
var (
	errBadPrefix = errors.New("wire: frame missing #AES: prefix")
	errBadInner  = errors.New("wire: inner event shorter than routing prefix")
)

const inboundRoutingPrefixLen = 53 // MD5(32) + "55555"(5) + "1234567891"(10) + ":"(1) + "5555"(4) + ":"(1)

func DecodeFrame(aesKey, frame []byte) ([]byte, error) {
	idx := bytes.Index(frame, []byte("#AES:"))
	if idx < 0 {
		return nil, errBadPrefix
	}
	ct := frame[idx+5:]
	pt, err := aesDecrypt(aesKey, IV, ct)
	if err != nil {
		return nil, err
	}
	// Unpad PKCS#7 first, then strip the leading '!' wazuh padding.
	pt = pkcs7Unpad(pt)
	i := 0
	for i < len(pt) && pt[i] == '!' {
		i++
	}
	compressed := pt[i:]
	inner, err := zlibDecompress(compressed)
	if err != nil {
		return nil, err
	}
	// Python's decoder skips MD5(32) + routing prefix without validation
	// (the manager's prefix bytes can differ from the agent-side literals).
	if len(inner) < inboundRoutingPrefixLen {
		return nil, errBadInner
	}
	return inner[inboundRoutingPrefixLen:], nil
}

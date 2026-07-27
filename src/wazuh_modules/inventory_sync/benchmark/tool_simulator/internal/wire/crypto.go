// Package wire implements the Wazuh remoted wire protocol (port 1514):
// length-prefix + AES-256-CBC + zlib + MD5 + framing. See
// docu/05-wire-protocol.md for the full reference.
package wire

import (
	"crypto/md5"
	"encoding/hex"
)

// DeriveAESKey returns the 32-byte AES-256 key used by an agent to encrypt
// frames sent to wazuh-remoted. See benchmark_sender.py _create_encryption_key.
//
//	sum1 = MD5_hex(MD5_hex(name) || MD5_hex(id))[:15]   (15 ASCII bytes)
//	sum2 = MD5_hex(managerKey)                          (32 ASCII bytes)
//	enc  = sum2 || sum1                                  (47 ASCII bytes)
//	key  = enc[:32]
func DeriveAESKey(managerKey, name, id string) []byte {
	hn := md5.Sum([]byte(name))
	hi := md5.Sum([]byte(id))
	concat := append([]byte(hex.EncodeToString(hn[:])), hex.EncodeToString(hi[:])...)
	sum1full := md5.Sum(concat)
	sum1 := []byte(hex.EncodeToString(sum1full[:]))[:15]

	hk := md5.Sum([]byte(managerKey))
	sum2 := []byte(hex.EncodeToString(hk[:]))

	enc := append(sum2, sum1...)
	return enc[:32]
}

#ifndef _RPMPGPVAL_H
#define _RPMPGPVAL_H

#include <rpm/rpmpgp.h>

typedef const struct pgpValTbl_s {
    int val;
    char const * const str;
} * pgpValTbl;

static struct pgpValTbl_s const pgpSigTypeTbl[] = {
    { PGPSIGTYPE_BINARY,	"Binary document signature" },
    { PGPSIGTYPE_TEXT,		"Text document signature" },
    { PGPSIGTYPE_STANDALONE,	"Standalone signature" },
    { PGPSIGTYPE_GENERIC_CERT,	"Generic certification of a User ID and Public Key" },
    { PGPSIGTYPE_PERSONA_CERT,	"Persona certification of a User ID and Public Key" },
    { PGPSIGTYPE_CASUAL_CERT,	"Casual certification of a User ID and Public Key" },
    { PGPSIGTYPE_POSITIVE_CERT,	"Positive certification of a User ID and Public Key" },
    { PGPSIGTYPE_SUBKEY_BINDING,"Subkey Binding Signature" },
    { PGPSIGTYPE_PRIMARY_BINDING,"Primary Binding Signature" },
    { PGPSIGTYPE_SIGNED_KEY,	"Signature directly on a key" },
    { PGPSIGTYPE_KEY_REVOKE,	"Key revocation signature" },
    { PGPSIGTYPE_SUBKEY_REVOKE,	"Subkey revocation signature" },
    { PGPSIGTYPE_CERT_REVOKE,	"Certification revocation signature" },
    { PGPSIGTYPE_TIMESTAMP,	"Timestamp signature" },
    { -1,			"Unknown signature type" },
};

static struct pgpValTbl_s const pgpPubkeyTbl[] = {
    { PGPPUBKEYALGO_RSA,	"RSA" },
    { PGPPUBKEYALGO_RSA_ENCRYPT,"RSA(Encrypt-Only)" },
    { PGPPUBKEYALGO_RSA_SIGN,	"RSA(Sign-Only)" },
    { PGPPUBKEYALGO_ELGAMAL_ENCRYPT,"Elgamal(Encrypt-Only)" },
    { PGPPUBKEYALGO_DSA,	"DSA" },
    { PGPPUBKEYALGO_EC,		"Elliptic Curve" },
    { PGPPUBKEYALGO_ECDSA,	"ECDSA" },
    { PGPPUBKEYALGO_ELGAMAL,	"Elgamal" },
    { PGPPUBKEYALGO_DH,		"Diffie-Hellman (X9.42)" },
    { PGPPUBKEYALGO_EDDSA,	"EdDSA" },
    { -1,			"Unknown public key algorithm" },
};

static struct pgpValTbl_s const pgpSymkeyTbl[] = {
    { PGPSYMKEYALGO_PLAINTEXT,	"Plaintext" },
    { PGPSYMKEYALGO_IDEA,	"IDEA" },
    { PGPSYMKEYALGO_TRIPLE_DES,	"3DES" },
    { PGPSYMKEYALGO_CAST5,	"CAST5" },
    { PGPSYMKEYALGO_BLOWFISH,	"BLOWFISH" },
    { PGPSYMKEYALGO_SAFER,	"SAFER" },
    { PGPSYMKEYALGO_DES_SK,	"DES/SK" },
    { PGPSYMKEYALGO_AES_128,	"AES(128-bit key)" },
    { PGPSYMKEYALGO_AES_192,	"AES(192-bit key)" },
    { PGPSYMKEYALGO_AES_256,	"AES(256-bit key)" },
    { PGPSYMKEYALGO_TWOFISH,	"TWOFISH(256-bit key)" },
    { PGPSYMKEYALGO_NOENCRYPT,	"no encryption" },
    { -1,			"Unknown symmetric key algorithm" },
};

static struct pgpValTbl_s const pgpCompressionTbl[] = {
    { PGPCOMPRESSALGO_NONE,	"Uncompressed" },
    { PGPCOMPRESSALGO_ZIP,	"ZIP" },
    { PGPCOMPRESSALGO_ZLIB, 	"ZLIB" },
    { PGPCOMPRESSALGO_BZIP2, 	"BZIP2" },
    { -1,			"Unknown compression algorithm" },
};

static struct pgpValTbl_s const pgpHashTbl[] = {
    { PGPHASHALGO_MD5,		"MD5" },
    { PGPHASHALGO_SHA1,		"SHA1" },
    { PGPHASHALGO_RIPEMD160,	"RIPEMD160" },
    { PGPHASHALGO_MD2,		"MD2" },
    { PGPHASHALGO_TIGER192,	"TIGER192" },
    { PGPHASHALGO_HAVAL_5_160,	"HAVAL-5-160" },
    { PGPHASHALGO_SHA256,	"SHA256" },
    { PGPHASHALGO_SHA384,	"SHA384" },
    { PGPHASHALGO_SHA512,	"SHA512" },
    { PGPHASHALGO_SHA224,	"SHA224" },
    { -1,			"Unknown hash algorithm" },
};

static struct pgpValTbl_s const pgpKeyServerPrefsTbl[] = {
    { 0x80,			"No-modify" },
    { -1,			"Unknown key server preference" },
};

static struct pgpValTbl_s const pgpSubTypeTbl[] = {
    { PGPSUBTYPE_SIG_CREATE_TIME,"signature creation time" },
    { PGPSUBTYPE_SIG_EXPIRE_TIME,"signature expiration time" },
    { PGPSUBTYPE_EXPORTABLE_CERT,"exportable certification" },
    { PGPSUBTYPE_TRUST_SIG,	"trust signature" },
    { PGPSUBTYPE_REGEX,		"regular expression" },
    { PGPSUBTYPE_REVOCABLE,	"revocable" },
    { PGPSUBTYPE_KEY_EXPIRE_TIME,"key expiration time" },
    { PGPSUBTYPE_ARR,		"additional recipient request" },
    { PGPSUBTYPE_PREFER_SYMKEY,	"preferred symmetric algorithms" },
    { PGPSUBTYPE_REVOKE_KEY,	"revocation key" },
    { PGPSUBTYPE_ISSUER_KEYID,	"issuer key ID" },
    { PGPSUBTYPE_NOTATION,	"notation data" },
    { PGPSUBTYPE_PREFER_HASH,	"preferred hash algorithms" },
    { PGPSUBTYPE_PREFER_COMPRESS,"preferred compression algorithms" },
    { PGPSUBTYPE_KEYSERVER_PREFERS,"key server preferences" },
    { PGPSUBTYPE_PREFER_KEYSERVER,"preferred key server" },
    { PGPSUBTYPE_PRIMARY_USERID,"primary user id" },
    { PGPSUBTYPE_POLICY_URL,	"policy URL" },
    { PGPSUBTYPE_KEY_FLAGS,	"key flags" },
    { PGPSUBTYPE_SIGNER_USERID,	"signer's user id" },
    { PGPSUBTYPE_REVOKE_REASON,	"reason for revocation" },
    { PGPSUBTYPE_FEATURES,	"features" },
    { PGPSUBTYPE_EMBEDDED_SIG,	"embedded signature" },
    { PGPSUBTYPE_ISSUER_FINGERPRINT,"issuer fingerprint" },

    { PGPSUBTYPE_INTERNAL_100,	"internal subpkt type 100" },
    { PGPSUBTYPE_INTERNAL_101,	"internal subpkt type 101" },
    { PGPSUBTYPE_INTERNAL_102,	"internal subpkt type 102" },
    { PGPSUBTYPE_INTERNAL_103,	"internal subpkt type 103" },
    { PGPSUBTYPE_INTERNAL_104,	"internal subpkt type 104" },
    { PGPSUBTYPE_INTERNAL_105,	"internal subpkt type 105" },
    { PGPSUBTYPE_INTERNAL_106,	"internal subpkt type 106" },
    { PGPSUBTYPE_INTERNAL_107,	"internal subpkt type 107" },
    { PGPSUBTYPE_INTERNAL_108,	"internal subpkt type 108" },
    { PGPSUBTYPE_INTERNAL_109,	"internal subpkt type 109" },
    { PGPSUBTYPE_INTERNAL_110,	"internal subpkt type 110" },
    { -1,			"Unknown signature subkey type" },
};

static struct pgpValTbl_s const pgpTagTbl[] = {
    { PGPTAG_PUBLIC_SESSION_KEY,"Public-Key Encrypted Session Key" },
    { PGPTAG_SIGNATURE,		"Signature" },
    { PGPTAG_SYMMETRIC_SESSION_KEY,"Symmetric-Key Encrypted Session Key" },
    { PGPTAG_ONEPASS_SIGNATURE,	"One-Pass Signature" },
    { PGPTAG_SECRET_KEY,	"Secret Key" },
    { PGPTAG_PUBLIC_KEY,	"Public Key" },
    { PGPTAG_SECRET_SUBKEY,	"Secret Subkey" },
    { PGPTAG_COMPRESSED_DATA,	"Compressed Data" },
    { PGPTAG_SYMMETRIC_DATA,	"Symmetrically Encrypted Data" },
    { PGPTAG_MARKER,		"Marker" },
    { PGPTAG_LITERAL_DATA,	"Literal Data" },
    { PGPTAG_TRUST,		"Trust" },
    { PGPTAG_USER_ID,		"User ID" },
    { PGPTAG_PUBLIC_SUBKEY,	"Public Subkey" },
    { PGPTAG_COMMENT_OLD,	"Comment (from OpenPGP draft)" },
    { PGPTAG_PHOTOID,		"PGP's photo ID" },
    { PGPTAG_ENCRYPTED_MDC,	"Integrity protected encrypted data" },
    { PGPTAG_MDC,		"Manipulaion detection code packet" },
    { PGPTAG_PRIVATE_60,	"Private #60" },
    { PGPTAG_COMMENT,		"Comment" },
    { PGPTAG_PRIVATE_62,	"Private #62" },
    { PGPTAG_CONTROL,		"Control (GPG)" },
    { -1,			"Unknown packet tag" },
};

static struct pgpValTbl_s const pgpArmorTbl[] = {
    { PGPARMOR_MESSAGE,		"MESSAGE" },
    { PGPARMOR_PUBKEY,		"PUBLIC KEY BLOCK" },
    { PGPARMOR_SIGNATURE,	"SIGNATURE" },
    { PGPARMOR_SIGNED_MESSAGE,	"SIGNED MESSAGE" },
    { PGPARMOR_FILE,		"ARMORED FILE" },
    { PGPARMOR_PRIVKEY,		"PRIVATE KEY BLOCK" },
    { PGPARMOR_SECKEY,		"SECRET KEY BLOCK" },
    { -1,			"Unknown armor block" }
};

static struct pgpValTbl_s const pgpArmorKeyTbl[] = {
    { PGPARMORKEY_VERSION,	"Version: " },
    { PGPARMORKEY_COMMENT,	"Comment: " },
    { PGPARMORKEY_MESSAGEID,	"MessageID: " },
    { PGPARMORKEY_HASH,		"Hash: " },
    { PGPARMORKEY_CHARSET,	"Charset: " },
    { -1,			"Unknown armor key" }
};

#endif /* _RPMPGPVAL_H */

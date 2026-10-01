#ifndef	H_RPMPGP
#define	H_RPMPGP

/** \ingroup rpmpgp
 * \file rpmpgp.h
 *
 * OpenPGP constants and structures from RFC-2440.
 *
 * Text from RFC-2440 in comments is
 *	Copyright (C) The Internet Society (1998).  All Rights Reserved.
 *
 * EdDSA algorithm identifier value taken from
 *      https://datatracker.ietf.org/doc/draft-ietf-openpgp-rfc4880bis/
 * This value is used in gnupg since version 2.1.0
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmcrypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmpgp
 */
typedef struct pgpDigParams_s * pgpDigParams;

/** \ingroup rpmpgp
 * The length (in bytes) of a binary (not hex encoded) key ID.
 */
#define PGP_KEYID_LEN 8

typedef uint8_t pgpKeyID_t[PGP_KEYID_LEN];

/** \ingroup rpmpgp
 * 4.3. Packet Tags
 */
typedef enum pgpTag_e {
    PGPTAG_RESERVED		=  0, /*!< Reserved/Invalid */
    PGPTAG_PUBLIC_SESSION_KEY	=  1, /*!< Public-Key Encrypted Session Key */
    PGPTAG_SIGNATURE		=  2, /*!< Signature */
    PGPTAG_SYMMETRIC_SESSION_KEY=  3, /*!< Symmetric-Key Encrypted Session Key*/
    PGPTAG_ONEPASS_SIGNATURE	=  4, /*!< One-Pass Signature */
    PGPTAG_SECRET_KEY		=  5, /*!< Secret Key */
    PGPTAG_PUBLIC_KEY		=  6, /*!< Public Key */
    PGPTAG_SECRET_SUBKEY	=  7, /*!< Secret Subkey */
    PGPTAG_COMPRESSED_DATA	=  8, /*!< Compressed Data */
    PGPTAG_SYMMETRIC_DATA	=  9, /*!< Symmetrically Encrypted Data */
    PGPTAG_MARKER		= 10, /*!< Marker */
    PGPTAG_LITERAL_DATA		= 11, /*!< Literal Data */
    PGPTAG_TRUST		= 12, /*!< Trust */
    PGPTAG_USER_ID		= 13, /*!< User ID */
    PGPTAG_PUBLIC_SUBKEY	= 14, /*!< Public Subkey */
    PGPTAG_COMMENT_OLD		= 16, /*!< Comment (from OpenPGP draft) */
    PGPTAG_PHOTOID		= 17, /*!< PGP's photo ID */
    PGPTAG_ENCRYPTED_MDC	= 18, /*!< Integrity protected encrypted data */
    PGPTAG_MDC			= 19, /*!< Manipulaion detection code packet */
    PGPTAG_PRIVATE_60		= 60, /*!< Private or Experimental Values */
    PGPTAG_COMMENT		= 61, /*!< Comment */
    PGPTAG_PRIVATE_62		= 62, /*!< Private or Experimental Values */
    PGPTAG_CONTROL		= 63  /*!< Control (GPG) */
} pgpTag;

/** \ingroup rpmpgp
 * 5.2.1. Signature Types
 */
typedef enum pgpSigType_e {
    PGPSIGTYPE_BINARY		 = 0x00, /*!< Binary document */
    PGPSIGTYPE_TEXT		 = 0x01, /*!< Canonical text document */
    PGPSIGTYPE_STANDALONE	 = 0x02, /*!< Standalone */
    PGPSIGTYPE_GENERIC_CERT	 = 0x10,
		/*!< Generic certification of a User ID & Public Key */
    PGPSIGTYPE_PERSONA_CERT	 = 0x11,
		/*!< Persona certification of a User ID & Public Key */
    PGPSIGTYPE_CASUAL_CERT	 = 0x12,
		/*!< Casual certification of a User ID & Public Key */
    PGPSIGTYPE_POSITIVE_CERT	 = 0x13,
		/*!< Positive certification of a User ID & Public Key */
    PGPSIGTYPE_SUBKEY_BINDING	 = 0x18, /*!< Subkey Binding */
    PGPSIGTYPE_PRIMARY_BINDING	 = 0x19, /*!< Primary Binding */
    PGPSIGTYPE_SIGNED_KEY	 = 0x1F, /*!< Signature directly on a key */
    PGPSIGTYPE_KEY_REVOKE	 = 0x20, /*!< Key revocation */
    PGPSIGTYPE_SUBKEY_REVOKE	 = 0x28, /*!< Subkey revocation */
    PGPSIGTYPE_CERT_REVOKE	 = 0x30, /*!< Certification revocation */
    PGPSIGTYPE_TIMESTAMP	 = 0x40  /*!< Timestamp */
} pgpSigType;

/** \ingroup rpmpgp
 * 9.1. Public Key Algorithms
 */
typedef enum pgpPubkeyAlgo_e {
    PGPPUBKEYALGO_RSA		=  1,	/*!< RSA */
    PGPPUBKEYALGO_RSA_ENCRYPT	=  2,	/*!< RSA(Encrypt-Only) */
    PGPPUBKEYALGO_RSA_SIGN	=  3,	/*!< RSA(Sign-Only) */
    PGPPUBKEYALGO_ELGAMAL_ENCRYPT = 16,	/*!< Elgamal(Encrypt-Only) */
    PGPPUBKEYALGO_DSA		= 17,	/*!< DSA */
    PGPPUBKEYALGO_EC		= 18,	/*!< Elliptic Curve */
    PGPPUBKEYALGO_ECDSA		= 19,	/*!< ECDSA */
    PGPPUBKEYALGO_ELGAMAL	= 20,	/*!< Elgamal */
    PGPPUBKEYALGO_DH		= 21,	/*!< Diffie-Hellman (X9.42) */
    PGPPUBKEYALGO_EDDSA		= 22	/*!< EdDSA */
} pgpPubkeyAlgo;

/** \ingroup rpmpgp
 * 9.2. Symmetric Key Algorithms
 */
typedef enum pgpSymkeyAlgo_e {
    PGPSYMKEYALGO_PLAINTEXT	=  0,	/*!< Plaintext */
    PGPSYMKEYALGO_IDEA		=  1,	/*!< IDEA */
    PGPSYMKEYALGO_TRIPLE_DES	=  2,	/*!< 3DES */
    PGPSYMKEYALGO_CAST5		=  3,	/*!< CAST5 */
    PGPSYMKEYALGO_BLOWFISH	=  4,	/*!< BLOWFISH */
    PGPSYMKEYALGO_SAFER		=  5,	/*!< SAFER */
    PGPSYMKEYALGO_DES_SK	=  6,	/*!< DES/SK */
    PGPSYMKEYALGO_AES_128	=  7,	/*!< AES(128-bit key) */
    PGPSYMKEYALGO_AES_192	=  8,	/*!< AES(192-bit key) */
    PGPSYMKEYALGO_AES_256	=  9,	/*!< AES(256-bit key) */
    PGPSYMKEYALGO_TWOFISH	= 10,	/*!< TWOFISH(256-bit key) */
    PGPSYMKEYALGO_NOENCRYPT	= 110	/*!< no encryption */
} pgpSymkeyAlgo;

/** \ingroup rpmpgp
 * 9.3. Compression Algorithms
 */
typedef enum pgpCompressAlgo_e {
    PGPCOMPRESSALGO_NONE	=  0,	/*!< Uncompressed */
    PGPCOMPRESSALGO_ZIP		=  1,	/*!< ZIP */
    PGPCOMPRESSALGO_ZLIB	=  2,	/*!< ZLIB */
    PGPCOMPRESSALGO_BZIP2	=  3	/*!< BZIP2 */
} pgpCompressAlgo;

/** \ingroup rpmpgp
 * 9.4. Hash Algorithms
 */
typedef enum pgpHashAlgo_e {
    PGPHASHALGO_MD5		=  1,	/*!< MD5 */
    PGPHASHALGO_SHA1		=  2,	/*!< SHA1 */
    PGPHASHALGO_RIPEMD160	=  3,	/*!< RIPEMD160 */
    PGPHASHALGO_MD2		=  5,	/*!< MD2 */
    PGPHASHALGO_TIGER192	=  6,	/*!< TIGER192 */
    PGPHASHALGO_HAVAL_5_160	=  7,	/*!< HAVAL-5-160 */
    PGPHASHALGO_SHA256		=  8,	/*!< SHA256 */
    PGPHASHALGO_SHA384		=  9,	/*!< SHA384 */
    PGPHASHALGO_SHA512		= 10,	/*!< SHA512 */
    PGPHASHALGO_SHA224		= 11,	/*!< SHA224 */
} pgpHashAlgo;

/** \ingroup rpmpgp
 * ECC Curves
 *
 * The following curve ids are private to rpm. PGP uses
 * oids to identify a curve.
 */
typedef enum pgpCurveId_e {
    PGPCURVE_NIST_P_256		=  1,	/*!< NIST P-256 */
    PGPCURVE_NIST_P_384		=  2,	/*!< NIST P-384 */
    PGPCURVE_NIST_P_521		=  3,	/*!< NIST P-521 */
    PGPCURVE_BRAINPOOL_P256R1	=  4,	/*!< brainpoolP256r1 */
    PGPCURVE_BRAINPOOL_P512R1	=  5,	/*!< brainpoolP512r1 */
    PGPCURVE_ED25519		=  6,	/*!< Ed25519 */
    PGPCURVE_CURVE25519		=  7,	/*!< Curve25519 */
} pgpCurveId;

/** \ingroup rpmpgp
 * 5.2.3.1. Signature Subpacket Specification
 */
typedef enum pgpSubType_e {
    PGPSUBTYPE_NONE		=   0, /*!< none */
    PGPSUBTYPE_SIG_CREATE_TIME	=   2, /*!< signature creation time */
    PGPSUBTYPE_SIG_EXPIRE_TIME	=   3, /*!< signature expiration time */
    PGPSUBTYPE_EXPORTABLE_CERT	=   4, /*!< exportable certification */
    PGPSUBTYPE_TRUST_SIG	=   5, /*!< trust signature */
    PGPSUBTYPE_REGEX		=   6, /*!< regular expression */
    PGPSUBTYPE_REVOCABLE	=   7, /*!< revocable */
    PGPSUBTYPE_KEY_EXPIRE_TIME	=   9, /*!< key expiration time */
    PGPSUBTYPE_ARR		=  10, /*!< additional recipient request */
    PGPSUBTYPE_PREFER_SYMKEY	=  11, /*!< preferred symmetric algorithms */
    PGPSUBTYPE_REVOKE_KEY	=  12, /*!< revocation key */
    PGPSUBTYPE_ISSUER_KEYID	=  16, /*!< issuer key ID */
    PGPSUBTYPE_NOTATION		=  20, /*!< notation data */
    PGPSUBTYPE_PREFER_HASH	=  21, /*!< preferred hash algorithms */
    PGPSUBTYPE_PREFER_COMPRESS	=  22, /*!< preferred compression algorithms */
    PGPSUBTYPE_KEYSERVER_PREFERS=  23, /*!< key server preferences */
    PGPSUBTYPE_PREFER_KEYSERVER	=  24, /*!< preferred key server */
    PGPSUBTYPE_PRIMARY_USERID	=  25, /*!< primary user id */
    PGPSUBTYPE_POLICY_URL	=  26, /*!< policy URL */
    PGPSUBTYPE_KEY_FLAGS	=  27, /*!< key flags */
    PGPSUBTYPE_SIGNER_USERID	=  28, /*!< signer's user id */
    PGPSUBTYPE_REVOKE_REASON	=  29, /*!< reason for revocation */
    PGPSUBTYPE_FEATURES		=  30, /*!< feature flags (gpg) */
    PGPSUBTYPE_EMBEDDED_SIG	=  32, /*!< embedded signature (gpg) */
    PGPSUBTYPE_ISSUER_FINGERPRINT= 33, /*!< issuer fingerprint */

    PGPSUBTYPE_INTERNAL_100	= 100, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_101	= 101, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_102	= 102, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_103	= 103, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_104	= 104, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_105	= 105, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_106	= 106, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_107	= 107, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_108	= 108, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_109	= 109, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_110	= 110, /*!< internal or user-defined */

    PGPSUBTYPE_CRITICAL		= 128  /*!< critical subpacket marker */
} pgpSubType;

/** \ingroup rpmpgp
 */
typedef enum pgpArmor_e {
    PGPARMOR_ERR_CRC_CHECK		= -7,
    PGPARMOR_ERR_BODY_DECODE		= -6,
    PGPARMOR_ERR_CRC_DECODE		= -5,
    PGPARMOR_ERR_NO_END_PGP		= -4,
    PGPARMOR_ERR_UNKNOWN_PREAMBLE_TAG	= -3,
    PGPARMOR_ERR_UNKNOWN_ARMOR_TYPE	= -2,
    PGPARMOR_ERR_NO_BEGIN_PGP		= -1,
#define	PGPARMOR_ERROR	PGPARMOR_ERR_NO_BEGIN_PGP
    PGPARMOR_NONE		=  0,
    PGPARMOR_MESSAGE		=  1, /*!< MESSAGE */
    PGPARMOR_PUBKEY		=  2, /*!< PUBLIC KEY BLOCK */
    PGPARMOR_SIGNATURE		=  3, /*!< SIGNATURE */
    PGPARMOR_SIGNED_MESSAGE	=  4, /*!< SIGNED MESSAGE */
    PGPARMOR_FILE		=  5, /*!< ARMORED FILE */
    PGPARMOR_PRIVKEY		=  6, /*!< PRIVATE KEY BLOCK */
    PGPARMOR_SECKEY		=  7  /*!< SECRET KEY BLOCK */
} pgpArmor;

/** \ingroup rpmpgp
 */
typedef enum pgpArmorKey_e {
    PGPARMORKEY_VERSION		= 1, /*!< Version: */
    PGPARMORKEY_COMMENT		= 2, /*!< Comment: */
    PGPARMORKEY_MESSAGEID	= 3, /*!< MessageID: */
    PGPARMORKEY_HASH		= 4, /*!< Hash: */
    PGPARMORKEY_CHARSET		= 5  /*!< Charset: */
} pgpArmorKey;

typedef enum pgpValType_e {
    PGPVAL_TAG			= 1,
    PGPVAL_ARMORBLOCK		= 2,
    PGPVAL_ARMORKEY		= 3,
    PGPVAL_SIGTYPE		= 4,
    PGPVAL_SUBTYPE		= 5,
    PGPVAL_PUBKEYALGO		= 6,
    PGPVAL_SYMKEYALGO		= 7,
    PGPVAL_COMPRESSALGO		= 8,
    PGPVAL_HASHALGO		= 9,
    PGPVAL_SERVERPREFS		= 10,
} pgpValType;

/** \ingroup rpmpgp
 * Return string representation of am OpenPGP value.
 * @param type		type of value
 * @param val		byte value to lookup
 * @return		string value of byte
 */
const char * pgpValString(pgpValType type, uint8_t val);

/** \ingroup rpmpgp
 * Calculate OpenPGP public key fingerprint.
 * @param pkt		OpenPGP packet (i.e. PGPTAG_PUBLIC_KEY)
 * @param pktlen	OpenPGP packet length (no. of bytes)
 * @param[out] fp	public key fingerprint
 * @param[out] fplen	public key fingerprint length
 * @return		0 on success, else -1
 */
int pgpPubkeyFingerprint(const uint8_t * pkt, size_t pktlen,
			 uint8_t **fp, size_t *fplen);

/** \ingroup rpmpgp
 * Calculate OpenPGP public key Key ID
 * @param pkt		OpenPGP packet (i.e. PGPTAG_PUBLIC_KEY)
 * @param pktlen	OpenPGP packet length (no. of bytes)
 * @param[out] keyid	public key Key ID
 * @return		0 on success, else -1
 */
int pgpPubkeyKeyID(const uint8_t * pkt, size_t pktlen, pgpKeyID_t keyid);

/** \ingroup rpmpgp
 * Parse a OpenPGP packet(s).
 * @param pkts		OpenPGP packet(s)
 * @param pktlen	OpenPGP packet(s) length (no. of bytes)
 * @param pkttype	Expected packet type (signature/key) or 0 for any
 * @param[out] ret	signature/pubkey packet parameters on success (alloced)
 * @return		-1 on error, 0 on success
 */
int pgpPrtParams(const uint8_t *pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret);

/** \ingroup rpmpgp
 * Parse a OpenPGP packet(s).
 * @param pkts		OpenPGP packet(s)
 * @param pktlen	OpenPGP packet(s) length (no. of bytes)
 * @param pkttype	Expected packet type (signature/key) or 0 for any
 * @param[out] ret	signature/pubkey packet parameters on success (alloced)
 * @param[out] lints	error messages and lints
 * @return		-1 on error, 0 on success
 */
int pgpPrtParams2(const uint8_t *pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret, char **lints);

/** \ingroup rpmpgp
 * Parse signing capable subkeys from OpenPGP packet(s).
 * @param pkts		OpenPGP packet(s)
 * @param pktlen	OpenPGP packet(s) length (no. of bytes)
 * @param mainkey	parameters of main key
 * @param subkeys	array of signing capable subkey parameters (alloced)
 * @param subkeysCount	count of subkeys
 * @return		-1 on error, 0 on success
 */
int pgpPrtParamsSubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount);

/** \ingroup rpmpgp
 * Parse the OpenPGP packets from one ASCII-armored block in a file.
 * @param fn		file name
 * @param[out] pkt	dearmored OpenPGP packet(s) (malloced)
 * @param[out] pktlen	dearmored OpenPGP packet(s) length in bytes
 * @return		type of armor found
 */
pgpArmor pgpReadPkts(const char * fn, uint8_t ** pkt, size_t * pktlen);

/** \ingroup rpmpgp
 * Parse the OpenPGP packets from one ASCII-armored block in memory.
 * @param armor		armored OpenPGP packet string
 * @param[out] pkt	dearmored OpenPGP packet(s) (malloced)
 * @param[out] pktlen	dearmored OpenPGP packet(s) length in bytes
 * @return		type of armor found
 */
pgpArmor pgpParsePkts(const char *armor, uint8_t ** pkt, size_t * pktlen);

/** \ingroup rpmpgp
 * Return a length of the first public key certificate in a buffer given
 * by pkts that contains one or more certificates. A public key certificate
 * consits of packets like Public key packet, User ID packet and so on.
 * In a buffer every certificate starts with Public key packet and it ends
 * with the start of the next certificate or with the end of the buffer.
 *
 * @param pkts		pointer to a buffer with certificates
 * @param pktslen	length of the buffer with certificates
 * @param certlen	length of the first certificate in the buffer
 * @return		0 on success
 */
int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen);

/** \ingroup rpmpgp
 * Lints the certificate.
 *
 * There are four cases:
 *
 * The packets do not describe a certificate: returns an error and
 * sets *explanation to NULL.
 *
 * The packets describe a certificate and the certificate is
 * completely unusable: returns an error and sets *explanation to a
 * human readable explanation.
 *
 * The packets describe a certificate and some components are not
 * usable: returns success, and sets *explanation to a human readable
 * explanation.
 *
 * The packets describe a certificate and there are no lints: returns
 * success, and sets *explanation to NULL.
 *
 * @param pkts	OpenPGP pointer to a buffer with certificates
 * @param pktslen	length of the buffer with certificates
 * @param[out] explanation	An optional lint to display to the user.
 * @return 		RPMRC_OK on success
 */
rpmRC pgpPubKeyLint(const uint8_t *pkts, size_t pktslen, char **explanation);

/** \ingroup rpmpgp
 * Wrap a OpenPGP packets in ascii armor for transport.
 * @param atype		type of armor
 * @param s		binary pkt data
 * @param ns		binary pkt data length
 * @return		formatted string
 */
char * pgpArmorWrap(int atype, const unsigned char * s, size_t ns);

/** \ingroup rpmpgp
 * Compare OpenPGP packet parameters
 * param p1		1st parameter container
 * param p2		2nd parameter container
 * return		1 if the parameters differ, 0 otherwise
 */
int pgpDigParamsCmp(pgpDigParams p1, pgpDigParams p2);

/** \ingroup rpmpgp
 * Retrieve OpenPGP algorithm parameters
 * param digp		parameter container
 * param algotype	PGPVAL_HASHALGO / PGPVAL_PUBKEYALGO
 * return		algorithm value, 0 on error
 */
unsigned int pgpDigParamsAlgo(pgpDigParams digp, unsigned int algotype);

/** \ingroup rpmpgp
 * Returns the issuer or the object's Key ID.
 *
 * If the object is a signature, then this returns the Key ID stored
 * in the first Issuer subpacket as a hex string.  (This is not
 * authenticated.)
 *
 * If the object is a certificate or a subkey, then this returns the key's
 * Key ID.
 *
 * The caller must not free the returned buffer.
 *
 * param digp		parameter container
 * return		an array of PGP_KEYID_LEN bytes.  If the issuer is
 * 			unknown, this returns an array with all zeros.
 */
const uint8_t *pgpDigParamsSignID(pgpDigParams digp);

/** \ingroup rpmpgp
 * Retrieve the primary User ID, if any.
 *
 * Returns the primary User ID, if any.
 *
 * If the object is a signature, then this returns NULL.
 *
 * If the object is a certificate or a subkey, then this returns the
 * certificate's primary User ID, if any.
 *
 * This interface does not provide a way for the caller to recognize
 * any embedded NUL characters.
 *
 * The caller must not free the returned buffer.
 *
 * param digp		parameter container
 * return		a string or NULL, if there is no primary User ID.
 */
const char *pgpDigParamsUserID(pgpDigParams digp);

/** \ingroup rpmpgp
 * Retrieve the object's version.
 *
 * Returns the object's version.
 *
 * If the object is a signature, then this returns the version of the
 * signature packet.
 *
 * If the object is a certificate, then this returns the version of the
 * primary key packet.
 *
 * If the object is a subkey, then this returns the version of the subkey's
 * key packet.
 *
 * param digp		parameter container
 * return		the object's version
 */
int pgpDigParamsVersion(pgpDigParams digp);

/** \ingroup rpmpgp
 * Retrieve the object's creation time.
 *
 * param digp		parameter container
 * return		seconds since the UNIX Epoch.
 */
uint32_t pgpDigParamsCreationTime(pgpDigParams digp);

/** \ingroup rpmpgp
 * Destroy parsed OpenPGP packet parameter(s).
 * @param digp		parameter container
 * @return		NULL always
 */
pgpDigParams pgpDigParamsFree(pgpDigParams digp);

/** \ingroup rpmpgp
 * Verify a PGP signature.
 * @param key		public key
 * @param sig		signature
 * @param hashctx	digest context
 * @return 		RPMRC_OK on success 
 */
rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx);

/** \ingroup rpmpgp
 * Verify a PGP signature and return a error message or lint.
 * @param key		public key
 * @param sig		signature
 * @param hashctx	digest context
 * @param lints	error messages and lints
 * @return 		RPMRC_OK on success
 */
rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx,
                          char **lints);

/** \ingroup rpmpgp
 * Return the type of a PGP signature. If `sig` is NULL, or is not a signature,
 * returns -1.
 *
 * @param sig		signature
 * @return 		type of the signature
 */
int pgpSignatureType(pgpDigParams sig);

/** \ingroup rpmpgp
 * Return a string identification of a PGP signature/pubkey.
 * @param digp		signature/pubkey container
 * @return		string describing the item and parameters
 */
char *pgpIdentItem(pgpDigParams digp);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMPGP */

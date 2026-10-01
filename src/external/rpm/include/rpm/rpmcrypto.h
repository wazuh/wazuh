#ifndef _RPMCRYPTO_H
#define _RPMCRYPTO_H

#include <rpm/rpmtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmcrypto
 */
typedef struct DIGEST_CTX_s * DIGEST_CTX;
typedef struct rpmDigestBundle_s * rpmDigestBundle;

/** \ingroup rpmcrypto
 * At this time these simply mirror PGPHASHALGO numbers. Once they
 * start * growing apart we'll need converters.
 */
typedef enum rpmHashAlgo_e {
    RPM_HASH_MD5		=  1,	/*!< MD5 */
    RPM_HASH_SHA1		=  2,	/*!< SHA1 */
    RPM_HASH_RIPEMD160		=  3,	/*!< RIPEMD160 */
    RPM_HASH_MD2		=  5,	/*!< MD2 */
    RPM_HASH_TIGER192		=  6,	/*!< TIGER192 */
    RPM_HASH_HAVAL_5_160	=  7,	/*!< HAVAL-5-160 */
    RPM_HASH_SHA256		=  8,	/*!< SHA256 */
    RPM_HASH_SHA384		=  9,	/*!< SHA384 */
    RPM_HASH_SHA512		= 10,	/*!< SHA512 */
    RPM_HASH_SHA224		= 11,	/*!< SHA224 */
} rpmHashAlgo;

/** \ingroup rpmcrypto
 * Bit(s) to control digest operation.
 */
enum rpmDigestFlags_e {
    RPMDIGEST_NONE      = 0
};

typedef rpmFlags rpmDigestFlags;

/** \ingroup rpmcrypto
 * Perform cryptography initialization.
 * It must be called before any cryptography can be used within rpm.
 * It's not normally necessary to call it directly as it's called in
 * general rpm initialization routines.
 * @return		0 on success, -1 on failure
 */
int rpmInitCrypto(void);

/** \ingroup rpmcrypto
 * Shutdown cryptography
 */
int rpmFreeCrypto(void);

/** \ingroup rpmcrypto
 * Duplicate a digest context.
 * @param octx		existing digest context
 * @return		duplicated digest context
 */
DIGEST_CTX rpmDigestDup(DIGEST_CTX octx);

/** \ingroup rpmcrypto
 * Obtain digest length in bytes.
 * @param hashalgo	type of digest
 * @return		digest length, zero on invalid algorithm
 */
size_t rpmDigestLength(int hashalgo);

/** \ingroup rpmcrypto
 * Initialize digest.
 * Set bit count to 0 and buffer to mysterious initialization constants.
 * @param hashalgo	type of digest
 * @param flags		bit(s) to control digest operation
 * @return		digest context
 */
DIGEST_CTX rpmDigestInit(int hashalgo, rpmDigestFlags flags);

/** \ingroup rpmcrypto
 * Update context with next plain text buffer.
 * @param ctx		digest context
 * @param data		next data buffer
 * @param len		no. bytes of data
 * @return		0 on success
 */
int rpmDigestUpdate(DIGEST_CTX ctx, const void * data, size_t len);

/** \ingroup rpmcrypto
 * Return digest and destroy context.
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 *
 * @param ctx		digest context
 * @param[out] datap	address of returned digest
 * @param[out] lenp	address of digest length
 * @param asAscii	return digest as ascii string?
 * @return		0 on success
 */
int rpmDigestFinal(DIGEST_CTX ctx, void ** datap, size_t * lenp, int asAscii);

/** \ingroup rpmcrypto
 * Create a new digest bundle.
 * @return		New digest bundle
 */
rpmDigestBundle rpmDigestBundleNew(void);

/** \ingroup rpmcrypto
 * Free a digest bundle and all contained digest contexts.
 * @param bundle	digest bundle
 * @return		NULL always
 */
rpmDigestBundle rpmDigestBundleFree(rpmDigestBundle bundle);

/** \ingroup rpmcrypto
 * Add a new type of digest to a bundle. Same as calling
 * rpmDigestBundleAddID() with algo == id value.
 * @param bundle	digest bundle
 * @param algo		type of digest
 * @param flags		bit(s) to control digest operation
 * @return		0 on success
 */
int rpmDigestBundleAdd(rpmDigestBundle bundle, int algo,
			rpmDigestFlags flags);

/** \ingroup rpmcrypto
 * Add a new type of digest to a bundle.
 * @param bundle	digest bundle
 * @param algo		type of digest
 * @param id		id of digest (arbitrary, must be > 0)
 * @param flags		bit(s) to control digest operation
 * @return		0 on success
 */
int rpmDigestBundleAddID(rpmDigestBundle bundle, int algo, int id,
			 rpmDigestFlags flags);

/** \ingroup rpmcrypto
 * Update contexts within bundle with next plain text buffer.
 * @param bundle	digest bundle
 * @param data		next data buffer
 * @param len		no. bytes of data
 * @return		0 on success
 */
int rpmDigestBundleUpdate(rpmDigestBundle bundle, const void *data, size_t len);

/** \ingroup rpmcrypto
 * Return digest from a bundle and destroy context, see rpmDigestFinal().
 *
 * @param bundle	digest bundle
 * @param id		id of digest to return
 * @param[out] datap	address of returned digest
 * @param[out] lenp	address of digest length
 * @param asAscii	return digest as ascii string?
 * @return		0 on success
 */
int rpmDigestBundleFinal(rpmDigestBundle bundle, int id,
			 void ** datap, size_t * lenp, int asAscii);

/** \ingroup rpmcrypto
 * Duplicate a digest context from a bundle.
 * @param bundle	digest bundle
 * @param id		id of digest to dup
 * @return		duplicated digest context
 */
DIGEST_CTX rpmDigestBundleDupCtx(rpmDigestBundle bundle, int id);


#ifdef __cplusplus
}
#endif

#endif /* _RPMCRYPTO_H */

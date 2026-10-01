#include "system.h"

#include <gcrypt.h>

#include <rpm/rpmcrypto.h>
#include <rpm/rpmstring.h>

#include "debug.h"

/**
 * MD5/SHA1 digest private data.
 */
struct DIGEST_CTX_s {
    rpmDigestFlags flags;	/*!< Bit(s) to control digest operation. */
    int algo;			/*!< Used hash algorithm */
    gcry_md_hd_t h;
};


/****************************  init   ************************************/

int rpmInitCrypto(void) {
    gcry_check_version (NULL);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;
}

int rpmFreeCrypto(void) {
    return 0;
}

/****************************  digest ************************************/

size_t rpmDigestLength(int hashalgo)
{
    switch (hashalgo) {
    case RPM_HASH_MD5:
	return 16;
    case RPM_HASH_SHA1:
	return 20;
    case RPM_HASH_SHA224:
	return 28;
    case RPM_HASH_SHA256:
	return 32;
    case RPM_HASH_SHA384:
	return 48;
    case RPM_HASH_SHA512:
	return 64;
    default:
	return 0;
    }
}

static int hashalgo2gcryalgo(int hashalgo)
{
    switch (hashalgo) {
    case RPM_HASH_MD5:
	return GCRY_MD_MD5;
    case RPM_HASH_SHA1:
	return GCRY_MD_SHA1;
    case RPM_HASH_SHA224:
	return GCRY_MD_SHA224;
    case RPM_HASH_SHA256:
	return GCRY_MD_SHA256;
    case RPM_HASH_SHA384:
	return GCRY_MD_SHA384;
    case RPM_HASH_SHA512:
	return GCRY_MD_SHA512;
    default:
	return 0;
    }
}

DIGEST_CTX rpmDigestInit(int hashalgo, rpmDigestFlags flags)
{
    gcry_md_hd_t h;
    DIGEST_CTX ctx;
    int gcryalgo = hashalgo2gcryalgo(hashalgo);

    if (!gcryalgo || gcry_md_open(&h, gcryalgo, 0) != 0)
	return NULL;

    ctx = (DIGEST_CTX)xcalloc(1, sizeof(*ctx));
    ctx->flags = flags;
    ctx->algo = hashalgo;
    ctx->h = h;
    return ctx;
}

int rpmDigestUpdate(DIGEST_CTX ctx, const void * data, size_t len)
{
    if (ctx == NULL)
	return -1;
    gcry_md_write(ctx->h, data, len);
    return 0;
}

int rpmDigestFinal(DIGEST_CTX ctx, void ** datap, size_t *lenp, int asAscii)
{
    unsigned char *digest;
    int digestlen;
    if (ctx == NULL)
	return -1;
    digest = gcry_md_read(ctx->h, 0);
    digestlen = rpmDigestLength(ctx->algo);
    if (!asAscii) {
	if (lenp)
	    *lenp = digestlen;
	if (datap) {
	    *datap = xmalloc(digestlen);
	    memcpy(*datap, digest, digestlen);
	}
    } else {
	if (lenp)
	    *lenp = 2 * digestlen + 1;
	if (datap) {
	    *datap = rpmhex((const uint8_t *)digest, digestlen);
	}
    }
    gcry_md_close(ctx->h);
    free(ctx);
    return 0;
}

DIGEST_CTX rpmDigestDup(DIGEST_CTX octx)
{
    DIGEST_CTX nctx = NULL;
    if (octx) {
        gcry_md_hd_t h;
	if (gcry_md_copy(&h, octx->h))
	    return NULL;
	nctx = (DIGEST_CTX)memcpy(xcalloc(1, sizeof(*nctx)), octx, sizeof(*nctx));
	nctx->h = h;
    }
    return nctx;
}

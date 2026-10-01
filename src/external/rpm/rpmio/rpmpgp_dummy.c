/* Dummy OpenPGP interface for compiling with minimal dependencies */

#include "system.h"
#include <rpm/rpmpgp.h>
#include "rpmpgpval.h"
#include "debug.h"

typedef struct pgpDigAlg_s * pgpDigAlg;

int pgpSignatureType(pgpDigParams _digp)
{
    return -1;
}

int pgpPubkeyFingerprint(const uint8_t * pkt, size_t pktlen,
                         uint8_t **fp, size_t *fplen)
{
    return -1;
}

int pgpPubkeyKeyID(const uint8_t * pkt, size_t pktlen, pgpKeyID_t keyid)
{
    return -1;
}

pgpDigParams pgpDigParamsFree(pgpDigParams digp)
{
    return NULL;
}

int pgpDigParamsCmp(pgpDigParams p1, pgpDigParams p2)
{
    return -1;
}

unsigned int pgpDigParamsAlgo(pgpDigParams digp, unsigned int algotype)
{
    return 0;
}

const uint8_t *pgpDigParamsSignID(pgpDigParams digp)
{
    return NULL;
}

const char *pgpDigParamsUserID(pgpDigParams digp)
{
    return NULL;
}

int pgpDigParamsVersion(pgpDigParams digp)
{
    return 0;
}

uint32_t pgpDigParamsCreationTime(pgpDigParams digp)
{
    return -1;
}

int pgpPrtParams(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret)
{
    return -1;
}

static char *not_supported(void)
{
    return xstrdup("RPM was compiled without OpenPGP support");
}

int pgpPrtParams2(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
                  pgpDigParams * ret, char **lints)
{
    if (lints)
        *lints = not_supported();
    return pgpPrtParams(pkts, pktlen, pkttype, ret);
}

int pgpPrtParamsSubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount)
{
    return -1;
}

rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
{
    return RPMRC_NOTFOUND;
}

rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints)
{
    if (lints)
        *lints = not_supported();
    return pgpVerifySignature(key, sig, hashctx);
}

pgpArmor pgpParsePkts(const char *armor, uint8_t ** pkt, size_t * pktlen)
{
    return PGPARMOR_NONE;
}

int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen)
{
    return -1;
}

char * pgpArmorWrap(int atype, const unsigned char * s, size_t ns)
{
    return NULL;
}

rpmRC pgpPubKeyLint(const uint8_t *pkts, size_t pktslen, char **explanation)
{
    *explanation = not_supported();
    return RPMRC_FAIL;
}

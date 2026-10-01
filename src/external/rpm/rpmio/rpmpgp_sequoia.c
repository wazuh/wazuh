// When rpm is configured to use Sequoia for the OpenPGP implementation
// ('configure --crypto=sequoia'), librpmio is linked against
// librpm_sequoia.
//
// librpm_sequoia can't directly implement the OpenPGP API, because
// librpmio won't reexport librpm_sequoia's symbols, and we don't want
// a program linking against librpmio to explicitly link against
// (i.e., need a DT_NEEDED entry for) librpm_sequoia.
//
// We can circumvent this problem by having librpm_sequoia provide
// identical functions under different names, and then having librpmio
// provide forwarders.  That's what this file does: it forwards pgpFoo
// to _pgpFoo.  It's a bit ugly, but it is better than a brittle,
// non-portable hack.

#include "rpmpgpval.h"

// Wrap a function.
//
// Define f to call _f, which has an identical function signature.
#define W(rt, f, params, args) \
  extern rt _##f params;       \
  rt f params {                \
    return _##f args;          \
  }

#ifdef __cplusplus
extern "C" {
#endif

W(int, pgpSignatureType, (pgpDigParams _digp), (_digp))
W(pgpDigParams, pgpDigParamsFree, (pgpDigParams digp), (digp))
W(int, pgpDigParamsCmp, (pgpDigParams p1, pgpDigParams p2), (p1, p2))
W(unsigned int, pgpDigParamsAlgo,
  (pgpDigParams digp, unsigned int algotype), (digp, algotype))
W(const uint8_t *, pgpDigParamsSignID, (pgpDigParams digp), (digp))
W(const char *, pgpDigParamsUserID, (pgpDigParams digp), (digp))
W(int, pgpDigParamsVersion, (pgpDigParams digp), (digp))
W(uint32_t, pgpDigParamsCreationTime, (pgpDigParams digp), (digp))
W(rpmRC, pgpVerifySignature,
  (pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx),
  (key, sig, hashctx))
W(rpmRC, pgpVerifySignature2,
  (pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints),
  (key, sig, hashctx, lints))
W(int, pgpPubkeyKeyID,
  (const uint8_t * pkt, size_t pktlen, pgpKeyID_t keyid),
  (pkt, pktlen, keyid))
W(int, pgpPubkeyFingerprint,
  (const uint8_t * pkt, size_t pktlen, uint8_t **fp, size_t *fplen),
  (pkt, pktlen, fp, fplen))
W(char *, pgpArmorWrap,
  (int atype, const unsigned char * s, size_t ns),
  (atype, s, ns))
W(int, pgpPubKeyCertLen,
  (const uint8_t *pkts, size_t pktslen, size_t *certlen),
  (pkts, pktslen, certlen))
W(int, pgpPrtParams,
  (const uint8_t *pkts, size_t pktlen, unsigned int pkttype, pgpDigParams *ret),
  (pkts, pktlen, pkttype, ret))
W(int, pgpPrtParams2,
  (const uint8_t *pkts, size_t pktlen, unsigned int pkttype, pgpDigParams *ret,
   char **lints),
  (pkts, pktlen, pkttype, ret, lints))
W(int, pgpPrtParamsSubkeys,
  (const uint8_t *pkts, size_t pktlen,
   pgpDigParams mainkey, pgpDigParams **subkeys,
   int *subkeysCount),
  (pkts, pktlen, mainkey, subkeys, subkeysCount))
W(pgpArmor, pgpParsePkts,
  (const char *armor, uint8_t ** pkt, size_t * pktlen),
  (armor, pkt, pktlen))
W(rpmRC, pgpPubKeyLint,
  (const uint8_t *pkts, size_t pktslen, char **explanation),
  (pkts, pktslen, explanation))
W(int, rpmInitCrypto, (void), ())
W(int, rpmFreeCrypto, (void), ())
W(DIGEST_CTX, rpmDigestInit, (int hashalgo, rpmDigestFlags flags),
  (hashalgo, flags))
W(DIGEST_CTX, rpmDigestDup, (DIGEST_CTX octx), (octx))
W(size_t, rpmDigestLength, (int hashalgo), (hashalgo))
W(int, rpmDigestUpdate, (DIGEST_CTX ctx, const void * data, size_t len),
  (ctx, data, len))
W(int, rpmDigestFinal,
  (DIGEST_CTX ctx, void ** datap, size_t *lenp, int asAscii),
  (ctx, datap, lenp, asAscii))

#ifdef __cplusplus
}
#endif


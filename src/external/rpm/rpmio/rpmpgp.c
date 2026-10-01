/** \ingroup rpmio signature
 * \file rpmio/rpmpgp.c
 * Routines to handle RFC-2440 detached signatures.
 */

#include "system.h"

#include <time.h>
#include <netinet/in.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>

#include "rpmpgpval.h"
#include "rpmio_internal.h"	/* XXX rpmioSlurp */

#include "debug.h"

static const char * pgpValStr(pgpValTbl vs, uint8_t val)
{
    do {
	if (vs->val == val)
	    break;
    } while ((++vs)->val != -1);
    return vs->str;
}

static pgpValTbl pgpValTable(pgpValType type)
{
    switch (type) {
    case PGPVAL_TAG:		return pgpTagTbl;
    case PGPVAL_ARMORBLOCK:	return pgpArmorTbl;
    case PGPVAL_ARMORKEY:	return pgpArmorKeyTbl;
    case PGPVAL_SIGTYPE:	return pgpSigTypeTbl;
    case PGPVAL_SUBTYPE:	return pgpSubTypeTbl;
    case PGPVAL_PUBKEYALGO:	return pgpPubkeyTbl;
    case PGPVAL_SYMKEYALGO:	return pgpSymkeyTbl;
    case PGPVAL_COMPRESSALGO:	return pgpCompressionTbl;
    case PGPVAL_HASHALGO: 	return pgpHashTbl;
    case PGPVAL_SERVERPREFS:	return pgpKeyServerPrefsTbl;
    default:
	break;
    }
    return NULL;
}

const char * pgpValString(pgpValType type, uint8_t val)
{
    pgpValTbl tbl = pgpValTable(type);
    return (tbl != NULL) ? pgpValStr(tbl, val) : NULL;
}

char *pgpIdentItem(pgpDigParams digp)
{
    char *id = NULL;
    if (digp) {
        char *signid = rpmhex(pgpDigParamsSignID(digp) + 4, PGP_KEYID_LEN - 4);
	rasprintf(&id, _("V%d %s/%s %s, key ID %s"),
                  pgpDigParamsVersion(digp),
                  pgpValString(PGPVAL_PUBKEYALGO,
				pgpDigParamsAlgo(digp, PGPVAL_PUBKEYALGO)),
                  pgpValString(PGPVAL_HASHALGO,
				pgpDigParamsAlgo(digp, PGPVAL_HASHALGO)),
                  (pgpSignatureType(digp) == -1) ? "Public Key" : "Signature",
                  signid);
        free(signid);
    } else {
	id = xstrdup(_("(none)"));
    }
    return id;
}

pgpArmor pgpReadPkts(const char * fn, uint8_t ** pkt, size_t * pktlen)
{
    uint8_t * b = NULL;
    ssize_t blen;
    pgpArmor ec = PGPARMOR_ERR_NO_BEGIN_PGP;	/* XXX assume failure */
    int rc = rpmioSlurp(fn, &b, &blen);
    if (rc == 0 && b != NULL && blen > 0) {
        ec = pgpParsePkts((const char *) b, pkt, pktlen);
    }
    free(b);
    return ec;
}

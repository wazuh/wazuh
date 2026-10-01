#include "system.h"

#include <pthread.h>

#include <rpm/rpmstring.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmkeyring.h>
#include <rpm/rpmbase64.h>

#include "debug.h"

int _print_pkts = 0;

struct rpmPubkey_s {
    uint8_t *pkt;
    size_t pktlen;
    pgpKeyID_t keyid;
    pgpDigParams pgpkey;
    int nrefs;
    pthread_rwlock_t lock;
};

struct rpmKeyring_s {
    struct rpmPubkey_s **keys;
    size_t numkeys;
    int nrefs;
    pthread_rwlock_t lock;
};

static int keyidcmp(const void *k1, const void *k2)
{
    const struct rpmPubkey_s *key1 = *(const struct rpmPubkey_s **) k1;
    const struct rpmPubkey_s *key2 = *(const struct rpmPubkey_s **) k2;
    
    return memcmp(key1->keyid, key2->keyid, sizeof(key1->keyid));
}

rpmKeyring rpmKeyringNew(void)
{
    rpmKeyring keyring = (rpmKeyring)xcalloc(1, sizeof(*keyring));
    keyring->keys = NULL;
    keyring->numkeys = 0;
    keyring->nrefs = 1;
    pthread_rwlock_init(&keyring->lock, NULL);
    return keyring;
}

rpmKeyring rpmKeyringFree(rpmKeyring keyring)
{
    if (keyring == NULL)
	return NULL;

    pthread_rwlock_wrlock(&keyring->lock);
    if (--keyring->nrefs == 0) {
	if (keyring->keys) {
	    for (int i = 0; i < keyring->numkeys; i++) {
		keyring->keys[i] = rpmPubkeyFree(keyring->keys[i]);
	    }
	    free(keyring->keys);
	}
	pthread_rwlock_unlock(&keyring->lock);
	pthread_rwlock_destroy(&keyring->lock);
	free(keyring);
    } else {
	pthread_rwlock_unlock(&keyring->lock);
    }
    return NULL;
}

static rpmPubkey rpmKeyringFindKeyid(rpmKeyring keyring, rpmPubkey key)
{
    rpmPubkey *found = NULL;
    if (key && keyring->keys) {
	found = (rpmPubkey *)bsearch(&key, keyring->keys, keyring->numkeys,
			sizeof(*keyring->keys), keyidcmp);
    }
    return found ? *found : NULL;
}

int rpmKeyringAddKey(rpmKeyring keyring, rpmPubkey key)
{
    int rc = 1; /* assume already seen key */
    if (keyring == NULL || key == NULL)
	return -1;

    /* check if we already have this key, but always wrlock for simplicity */
    pthread_rwlock_wrlock(&keyring->lock);
    if (!rpmKeyringFindKeyid(keyring, key)) {
	keyring->keys = xrealloc(keyring->keys,
				 (keyring->numkeys + 1) * sizeof(rpmPubkey));
	keyring->keys[keyring->numkeys] = rpmPubkeyLink(key);
	keyring->numkeys++;
	qsort(keyring->keys, keyring->numkeys, sizeof(*keyring->keys),
		keyidcmp);
	rc = 0;
    }
    pthread_rwlock_unlock(&keyring->lock);

    return rc;
}

rpmKeyring rpmKeyringLink(rpmKeyring keyring)
{
    if (keyring) {
	pthread_rwlock_wrlock(&keyring->lock);
	keyring->nrefs++;
	pthread_rwlock_unlock(&keyring->lock);
    }
    return keyring;
}

rpmPubkey rpmPubkeyRead(const char *filename)
{
    uint8_t *pkt = NULL;
    size_t pktlen;
    rpmPubkey key = NULL;

    if (pgpReadPkts(filename, &pkt, &pktlen) <= 0) {
	goto exit;
    }
    key = rpmPubkeyNew(pkt, pktlen);
    free(pkt);

exit:
    return key;
}

rpmPubkey rpmPubkeyNew(const uint8_t *pkt, size_t pktlen)
{
    rpmPubkey key = NULL;
    pgpDigParams pgpkey = NULL;
    pgpKeyID_t keyid;
    
    if (pkt == NULL || pktlen == 0)
	goto exit;

    if (pgpPubkeyKeyID(pkt, pktlen, keyid))
	goto exit;

    if (pgpPrtParams(pkt, pktlen, PGPTAG_PUBLIC_KEY, &pgpkey))
	goto exit;

    key = (rpmPubkey)xcalloc(1, sizeof(*key));
    key->pkt = (uint8_t *)xmalloc(pktlen);
    key->pktlen = pktlen;
    key->pgpkey = pgpkey;
    key->nrefs = 1;
    memcpy(key->pkt, pkt, pktlen);
    memcpy(key->keyid, keyid, sizeof(keyid));
    pthread_rwlock_init(&key->lock, NULL);

exit:
    return key;
}

rpmPubkey *rpmGetSubkeys(rpmPubkey mainkey, int *count)
{
    rpmPubkey *subkeys = NULL;
    pgpDigParams *pgpsubkeys = NULL;
    int pgpsubkeysCount = 0;
    int i;

    if (mainkey && !pgpPrtParamsSubkeys(mainkey->pkt, mainkey->pktlen,
			mainkey->pgpkey, &pgpsubkeys, &pgpsubkeysCount)) {

	subkeys = (rpmPubkey *)xmalloc(pgpsubkeysCount * sizeof(*subkeys));

	for (i = 0; i < pgpsubkeysCount; i++) {
	    rpmPubkey subkey = (rpmPubkey)xcalloc(1, sizeof(*subkey));
	    subkeys[i] = subkey;

	    /* Packets with all subkeys already stored in main key */
	    subkey->pkt = NULL;
	    subkey->pktlen = 0;

	    subkey->pgpkey = pgpsubkeys[i];
	    memcpy(subkey->keyid, pgpDigParamsSignID(pgpsubkeys[i]), PGP_KEYID_LEN);
	    subkey->nrefs = 1;
	    pthread_rwlock_init(&subkey->lock, NULL);
	}
	free(pgpsubkeys);
    }
    *count = pgpsubkeysCount;

    return subkeys;
}

rpmPubkey rpmPubkeyFree(rpmPubkey key)
{
    if (key == NULL)
	return NULL;

    pthread_rwlock_wrlock(&key->lock);
    if (--key->nrefs == 0) {
	pgpDigParamsFree(key->pgpkey);
	free(key->pkt);
	pthread_rwlock_unlock(&key->lock);
	pthread_rwlock_destroy(&key->lock);
	free(key);
    } else {
	pthread_rwlock_unlock(&key->lock);
    }
    return NULL;
}

rpmPubkey rpmPubkeyLink(rpmPubkey key)
{
    if (key) {
	pthread_rwlock_wrlock(&key->lock);
	key->nrefs++;
	pthread_rwlock_unlock(&key->lock);
    }
    return key;
}

char * rpmPubkeyBase64(rpmPubkey key)
{
    char *enc = NULL;

    if (key) {
	pthread_rwlock_rdlock(&key->lock);
	enc = rpmBase64Encode(key->pkt, key->pktlen, -1);
	pthread_rwlock_unlock(&key->lock);
    }
    return enc;
}

pgpDigParams rpmPubkeyPgpDigParams(rpmPubkey key)
{
    pgpDigParams params= NULL;

    if (key) {
	params = key->pgpkey;
    }
    return params;
}

static rpmPubkey findbySig(rpmKeyring keyring, pgpDigParams sig)
{
    rpmPubkey key = NULL;

    if (keyring && sig) {
	struct rpmPubkey_s needle;
	memset(&needle, 0, sizeof(needle));
	memcpy(needle.keyid, pgpDigParamsSignID(sig), PGP_KEYID_LEN);
	
	key = rpmKeyringFindKeyid(keyring, &needle);
	if (key) {
	    pgpDigParams pub = key->pgpkey;
	    /* Do the parameters match the signature? */
	    if ((pgpDigParamsAlgo(sig, PGPVAL_PUBKEYALGO)
                 != pgpDigParamsAlgo(pub, PGPVAL_PUBKEYALGO)) ||
                memcmp(pgpDigParamsSignID(sig), pgpDigParamsSignID(pub),
                       PGP_KEYID_LEN)) {
		key = NULL;
	    }
	}
    }
    return key;
}

rpmRC rpmKeyringVerifySig(rpmKeyring keyring, pgpDigParams sig, DIGEST_CTX ctx)
{
    rpmRC rc = RPMRC_FAIL;

    if (keyring)
	pthread_rwlock_rdlock(&keyring->lock);

    if (sig && ctx) {
	pgpDigParams pgpkey = NULL;
	rpmPubkey key = findbySig(keyring, sig);

	if (key)
	    pgpkey = key->pgpkey;

	/* We call verify even if key not found for a signature sanity check */
	char *lints = NULL;
	rc = pgpVerifySignature2(pgpkey, sig, ctx, &lints);
	if (lints) {
	    rpmlog(rc ? RPMLOG_ERR : RPMLOG_WARNING, "%s\n", lints);
	    free(lints);
	}
    }

    if (keyring)
	pthread_rwlock_unlock(&keyring->lock);

    return rc;
}

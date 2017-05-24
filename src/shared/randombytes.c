#ifndef WIN32
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "shared.h"


void randombytes(void *ptr, size_t length)
{
    char failed = 0;

#ifdef WIN32
    static HCRYPTPROV prov = 0;

    if (prov == 0) {
        if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 0)) {
            if (GetLastError() == (DWORD)NTE_BAD_KEYSET) {
                debug1("%s: DEBUG: No default container was found. Attempting to create default container.", __local_name);

                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                    merror("%s: ERROR: CryptAcquireContext: (%lx)", __local_name, GetLastError());
                    failed = 1;
                }
            } else {
                merror("%s: ERROR: CryptAcquireContext: (%lx)", __local_name, GetLastError());
                failed = 1;
            }
        }
    }
    if (!failed && !CryptGenRandom(prov, length, ptr)) {
        failed = 1;
    }
#else
    static int fh = -1;
    ssize_t ret;

    if (fh < 0 && (fh = open("/dev/urandom", O_RDONLY), fh < 0 && (fh = open("/dev/random", O_RDONLY), fh < 0))) {
        failed = 1;
    } else {
        ret = read(fh, ptr, length);

        if (ret < 0 || (size_t)ret != length) {
            failed = 1;
        }
    }

#endif

    if (failed) {
        ErrorExit("%s: ERROR: randombytes failed for all possible methods for accessing random data", __local_name);
    }
}

void srandom_init(void)
{
#ifndef WIN32
#ifdef __OpenBSD__
    srandomdev();
#else
    unsigned int seed;
    randombytes(&seed, sizeof seed);
    srandom(seed);
#endif /* !__OpenBSD__ */
#endif /* !WIN32 */
}

int os_random(void) {
	int myrandom;
	randombytes(&myrandom, sizeof(myrandom));
	return myrandom % RAND_MAX;
}

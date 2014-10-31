#ifdef WIN32
#include "windows.h"
#else
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
            failed = 1;
        }
    }
    if (!failed && !CryptGenRandom(prov, length, ptr)) {
        failed = 1;
    }

    #else

    int fh;
    if ((fh = open("/dev/urandom", O_RDONLY)) >= 0 || (fh = open("/dev/random", O_RDONLY)) >= 0) {
        const ssize_t ret = read(fh, ptr, length);
        if (ret < 0 || (size_t) ret != length) {
            failed = 1;
        }
        close(fh);
    } else {
        failed = 1;
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
    #endif  // __OpenBSD__
    #endif  // Win32

}

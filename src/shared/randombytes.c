#ifdef WIN32
#include "windows.h"
#else
#include <sys/stat.h> 
#include <fcntl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "debug_op.h"


void randombytes(void *ptr, unsigned int length)
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
    FILE *fh;
    if ((fh = open("/dev/urandom", O_RDONLY)) >= 0 || (fh = open("/dev/random", O_RDONLY)) >= 0) {
        if (fread(ptr, length, 1, fh) == 0) {
            failed = 1;
        }
        fclose(fh);
    } else {
        failed = 1;
    }
#endif
    /*
     * yes, this is horrible error handling but we don't have better
     * options from here and I don't want to start changing the design
     * of the library
     */
    if (failed) {
        ErrorExit("Error in randombytes failed on all possiable methods for accessing random data");
        exit(1);
    }
}

void srandom_init(void)
{

    #ifndef WIN32
    unsigned int seed; 
    #ifdef __OpenBSD__
    srandomdev();
    #else
    randombytes(&seed, sizeof seed);
    srandom(seed);
    #endif  // __OpenBSD__
    #endif  // Win32

}

/*
 * Copyright (C) 2015, Wazuh Inc.
 * Contributed by Jeremy Rossi (@jrossi)
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

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
                mdebug1("No default container was found. Attempting to create default container.");

                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                    merror("CryptAcquireContext Flag: NewKeySet (1): (%lx)", GetLastError());
                    failed = 1;
                }
            }else if(GetLastError() == (DWORD)NTE_KEYSET_ENTRY_BAD){
                mwarn("The agent's RSA key container for the random generator is corrupt. Resetting container...");

                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET)){
                    merror("CryptAcquireContext Flag: DeleteKeySet: (%lx)", GetLastError());
                    failed = 1;
                }
                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                    merror("CryptAcquireContext Flag: NewKeySet (2): (%lx)", GetLastError());
                    failed = 1;
                }
            } else {
                merror("CryptAcquireContext no Flag: (%lx)", GetLastError());
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

    if (fh < 0 && (fh = open("/dev/urandom", O_RDONLY | O_CLOEXEC), fh < 0 && (fh = open("/dev/random", O_RDONLY | O_CLOEXEC), fh < 0))) {
        failed = 1;
    } else {
        ret = read(fh, ptr, length);

        if (ret < 0 || (size_t)ret != length) {
            failed = 1;
        }
    }

#endif

    if (failed) {
        merror_exit("randombytes failed for all possible methods for accessing random data");
    }
}

void srandom_init(void)
{
    unsigned int seed;
    randombytes(&seed, sizeof seed);
    srandom(seed);
}

int os_random(void) {
	int myrandom;
	randombytes(&myrandom, sizeof(myrandom));
	return myrandom % RAND_MAX;
}

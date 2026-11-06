/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OPENSSL_INIT_H
#define OPENSSL_INIT_H

#include <openssl/crypto.h>
#include "debug_op.h"

/* NO_ATEXIT keeps OPENSSL_cleanup() out of exit(), where it would free OpenSSL state under threads that still use it.
 * Only the first initialization of a process can set it, so daemons call w_openssl_init() before any other OpenSSL use. */
#define W_OPENSSL_INIT_OPTS (OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | \
                             OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT)

static inline void w_openssl_init(void) {
    if (!OPENSSL_init_crypto(W_OPENSSL_INIT_OPTS, NULL)) {
        mwarn("OpenSSL initialization failed: OPENSSL_init_crypto() returned an error.");
    }
}

#endif /* OPENSSL_INIT_H */

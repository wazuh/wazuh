/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/blowfish Library
 * APIs for many crypto operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include "bf_op.h"

typedef unsigned char uchar;


int OS_BF_Str(const char *input, char *output, const char *charkey, long size, short int action)
{
    int len, final_len;
    static unsigned char iv[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    // As of OpenSSL 3.0, Blowfish has been moved to the legacy provider
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, (const unsigned char *)charkey, iv, action)) {
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        return 0;
    }

    if (!EVP_CipherUpdate(ctx, (unsigned char *)output, &len, (const unsigned char *)input, size)) {
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        return 0;
    }

    if (!EVP_CipherFinal_ex(ctx, output + len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(legacy);
    return 1; // Success
}

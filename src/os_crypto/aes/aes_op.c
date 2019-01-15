/* OS_crypto/AES Library
 * Copyright (C) 2015-2019, Wazuh Inc.
 * March 12, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "aes_op.h"

typedef unsigned char uchar;


int OS_AES_Str(const char *input, char *output, const char *charkey,
              long size, short int action)
{
    static unsigned char *iv = (unsigned char *)"FEDCBA0987654321";

    if(action == OS_ENCRYPT)
    {
        return encrypt_AES((const uchar *)input, (int)size,(uchar *)charkey, iv,(uchar *)output);
    }
    else
    {
        return decrypt_AES((const uchar *)input, (int)size,(uchar *)charkey, iv,(uchar *)output);
    }
}

int encrypt_AES(const unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
  {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto end;
    }

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        goto end;
    }

	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        goto end;
    }

	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ciphertext_len = 0;
        goto end;
    }

	ciphertext_len += len;

end:
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt_AES(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
  {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto end;
    }

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        goto end;
    }

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        goto end;
    }

	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        plaintext_len = 0;
        goto end;
    }

	plaintext_len += len;

end:
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

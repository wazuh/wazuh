/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/aes Library
 * APIs for many crypto operations
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
        decrypt_AES((const uchar *)input, (int)size,(uchar *)charkey, iv,(uchar *)output);
    }

    return (1);
}

int encrypt_AES(const unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
  {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
  
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	  handleErrors();
  
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	  handleErrors();
	ciphertext_len = len;
  
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;
  
	EVP_CIPHER_CTX_free(ctx);
  
	return ciphertext_len;
}

int decrypt_AES(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
  {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
  
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	  handleErrors();
  
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	  handleErrors();
	plaintext_len = len;
  
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;
  
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

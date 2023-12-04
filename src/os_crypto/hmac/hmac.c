/*
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 21, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "headers/defs.h"
#include "../sha1/sha1_op.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "hmac.h"

int OS_HMAC_SHA1_Str(const char *key, const char *text, os_sha1 output)
{
    unsigned char result[SHA_DIGEST_LENGTH + 1];
    unsigned char o_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char i_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char key_temp[HMAC_SHA1_BLOCKSIZE + 1];

    int i;
    size_t key_length;
    size_t text_length;

    key_length = strlen(key);
    text_length = strlen(text);

    if (key_length > HMAC_SHA1_BLOCKSIZE){
        os_sha1 sha_key;
        OS_SHA1_Str(key, key_length, sha_key);
        key_length = strlen(sha_key);
        memcpy(key_temp, sha_key, key_length);
    }
    else {
        memcpy(key_temp, key, key_length);
    }

    memset(o_key_pad, 0, sizeof(o_key_pad));
    memset(i_key_pad, 0, sizeof(i_key_pad));
    memcpy(o_key_pad, key_temp, key_length);
    memcpy(i_key_pad, key_temp, key_length);

    for (i = 0; i < HMAC_SHA1_BLOCKSIZE; i++){
        o_key_pad[i] ^= 0x5c;
        i_key_pad[i] ^= 0x36;
    }

    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    if (!sha1_ctx) {
        return -1;
    }

    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestUpdate(sha1_ctx, i_key_pad, HMAC_SHA1_BLOCKSIZE);
    EVP_DigestUpdate(sha1_ctx, text, text_length);
    EVP_DigestFinal(sha1_ctx, result, NULL);
    EVP_MD_CTX_free(sha1_ctx);
    sha1_ctx = NULL;

    sha1_ctx = EVP_MD_CTX_new();
    if (!sha1_ctx) {
        return -1;
    }

    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestUpdate(sha1_ctx, o_key_pad, HMAC_SHA1_BLOCKSIZE);
    EVP_DigestUpdate(sha1_ctx, result, SHA_DIGEST_LENGTH);
    EVP_DigestFinal(sha1_ctx, result, NULL);
    EVP_MD_CTX_free(sha1_ctx);

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(output + i * 2, 3, "%02x", result[i]);
    }

    return 0;
}

int OS_HMAC_SHA1_File(const char *key, const char *file_path, os_sha1 output, int mode)
{
    unsigned char o_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char i_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char key_temp[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char result[SHA_DIGEST_LENGTH + 1];
    unsigned char buffer[2048 + 2];

    int i;
    size_t key_length;
    FILE *fp;

    key_length = strlen(key);

    if (key_length > HMAC_SHA1_BLOCKSIZE){
        os_sha1 sha_key;
        OS_SHA1_Str(key, key_length, sha_key);
        key_length = strlen(sha_key);
        memcpy(key_temp, sha_key, key_length);
    } else {
      memcpy(key_temp, key, key_length);
    }

    memset(o_key_pad, 0, sizeof(o_key_pad));
    memset(i_key_pad, 0, sizeof(i_key_pad));
    memcpy(o_key_pad, key_temp, key_length);
    memcpy(i_key_pad, key_temp, key_length);

    for (i = 0; i < HMAC_SHA1_BLOCKSIZE; i++){
        o_key_pad[i] ^= 0x5c;
        i_key_pad[i] ^= 0x36;
    }

    fp = fopen(file_path, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return -1;
    }

    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    if (!sha1_ctx) {
        return -1;
    }
    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestUpdate(sha1_ctx, i_key_pad, HMAC_SHA1_BLOCKSIZE);

    while ((i = fread(buffer, 1, 2048, fp)) > 0) {
        buffer[i] = '\0';
        EVP_DigestUpdate(sha1_ctx, buffer, i);
    }

    EVP_DigestFinal(sha1_ctx, result, NULL);
    EVP_MD_CTX_free(sha1_ctx);
    sha1_ctx = NULL;

    sha1_ctx = EVP_MD_CTX_new();
    if (!sha1_ctx) {
        return -1;
    }
    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestUpdate(sha1_ctx, o_key_pad, HMAC_SHA1_BLOCKSIZE);
    EVP_DigestUpdate(sha1_ctx, result, HMAC_SHA1_BLOCKSIZE);
    EVP_DigestFinal(sha1_ctx, result, NULL);
    EVP_MD_CTX_free(sha1_ctx);

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(output + i * 2, 3, "%02x", result[i]);
    }

    fclose(fp);

    return 0;
}

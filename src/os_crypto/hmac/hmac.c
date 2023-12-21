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
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
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
    SHA_CTX context;

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

    SHA1_Init(&context);

    SHA1_Update(&context, i_key_pad, HMAC_SHA1_BLOCKSIZE);
    SHA1_Update(&context, text, text_length);

    SHA1_Final(result, &context);


    SHA1_Init(&context);

    SHA1_Update(&context, o_key_pad, HMAC_SHA1_BLOCKSIZE);
    SHA1_Update(&context, result, SHA_DIGEST_LENGTH);

    SHA1_Final(result, &context);

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(output + i * 2, 3, "%02x", result[i]);
    }

    return 0;
}

int OS_HMAC_SHA1_File(const char *key, const char *file_path, os_sha1 output, int mode)
{
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned char buffer[2048 + 2];

    int i;
    int ret = -1;
    FILE *fp;
    size_t result_len, key_length;
    os_sha1 sha_key;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];

    fp = fopen(file_path, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return -1;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        goto cleanup;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        goto cleanup;
    }

    key_length = strlen(key);
    if (key_length > HMAC_SHA1_BLOCKSIZE){
        OS_SHA1_Str(key, key_length, sha_key);
        key = sha_key;
        key_length = SHA_DIGEST_LENGTH;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA1", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, key_length);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, (unsigned char *)key, strlen(key), params)) {
        goto cleanup;
    }

    while ((i = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (!EVP_MAC_update(ctx, buffer, i)) {
            goto cleanup;
        }
    }

    result_len = sizeof(result);
    if (!EVP_MAC_final(ctx, result, &result_len, sizeof(result))) {
        goto cleanup;
    }

    if ((result_len * 2) + 1 > sizeof(os_sha1)) {
        goto cleanup;
    }

    for (i = 0; i < result_len; i++) {
        snprintf(output + i * 2, 3, "%02x", result[i]);
    }

    output[result_len * 2] = '\0';
    ret = 0;

cleanup:
    fclose(fp);

    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }

    if (mac) {
        EVP_MAC_free(mac);
    }

    return ret;
}

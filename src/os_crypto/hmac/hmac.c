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


#include "file_op.h"
#include "headers/defs.h"
#include "../sha1/sha1_op.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "hmac.h"

int OS_HMAC_SHA1_Str(const char *key, const char *text, os_sha1 output)
{
    unsigned char result[EVP_MAX_MD_SIZE];
    size_t len, key_length;
    EVP_MAC *hmac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    os_sha1 sha_key;
    int ret = -1;

    hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) {
        goto cleanup;
    }

    ctx = EVP_MAC_CTX_new(hmac);
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
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void*)key, key_length);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, (unsigned char *)key, strlen(key), params)) {
        goto cleanup;
    }

    if (!EVP_MAC_update(ctx, (unsigned char *)text, strlen(text))) {
        goto cleanup;
    }

    if (!EVP_MAC_final(ctx, result, &len, sizeof(result))) {
        goto cleanup;
    }

    if ((len * 2) + 1 > sizeof(os_sha1)) {
        goto cleanup;
    }

    for (size_t i = 0; i < len; i++) {
        snprintf(output + i * 2, 3, "%02x", result[i]);
    }

    output[len * 2] = '\0';
    ret = 0;

cleanup:
    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }

    if (hmac) {
        EVP_MAC_free(hmac);
    }

    return ret;
}

int OS_HMAC_SHA1_File(const char *key, const char *file_path, os_sha1 output, int mode)
{
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned char buffer[2048 + 2];

    int ret = -1;
    FILE *fp;
    size_t i, result_len, key_length;
    os_sha1 sha_key;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];

    fp = wfopen(file_path, mode == OS_BINARY ? "rb" : "r");
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
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void*)key, key_length);
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

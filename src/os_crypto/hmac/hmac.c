/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Jun 21, 2017.
 *
 * This program is a free software; you can redistribute it
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
#include "hmac.h"

int OS_HMAC_SHA1_Str(const char *key, const char *text, os_sha1 output)
{
    unsigned char result[SHA_DIGEST_LENGTH + 1];
    unsigned char o_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char i_key_pad[HMAC_SHA1_BLOCKSIZE + 1];

    int i;
    size_t key_length;
    size_t text_length;
    SHA_CTX context;

    key_length = strlen(key);
    text_length = strlen(text);

    if (key_length > HMAC_SHA1_BLOCKSIZE){
        os_sha1 sha_key;
        OS_SHA1_Str(key, key_length, sha_key);
        key = sha_key;
        key_length = SHA_DIGEST_LENGTH;
    }

    memset(o_key_pad, 0, sizeof(o_key_pad));
    memset(i_key_pad, 0, sizeof(i_key_pad));
    memcpy(o_key_pad, key, key_length);
    memcpy(i_key_pad, key, key_length);

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
    unsigned char o_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char i_key_pad[HMAC_SHA1_BLOCKSIZE + 1];
    unsigned char result[SHA_DIGEST_LENGTH + 1];
    unsigned char buffer[2048 + 2];
    int i;
    size_t key_length;
    SHA_CTX context;
    FILE *fp;

    key_length = strlen(key);

    if (key_length > HMAC_SHA1_BLOCKSIZE){
        os_sha1 sha_key;
        OS_SHA1_Str(key, key_length, sha_key);
        key = sha_key;
        key_length = SHA_DIGEST_LENGTH;
    }

    memset(o_key_pad, 0, sizeof(o_key_pad));
    memset(i_key_pad, 0, sizeof(i_key_pad));
    memcpy(o_key_pad, key, key_length);
    memcpy(i_key_pad, key, key_length);

    for (i = 0; i < HMAC_SHA1_BLOCKSIZE; i++){
        o_key_pad[i] ^= 0x5c;
        i_key_pad[i] ^= 0x36;
    }

    fp = fopen(file_path, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return -1;
    }

    SHA1_Init(&context);

    SHA1_Update(&context, i_key_pad, HMAC_SHA1_BLOCKSIZE);

    while ((i = fread(buffer, 1, 2048, fp)) > 0) {
        buffer[i] = '\0';
        SHA1_Update(&context, buffer, i);
    }

    SHA1_Final(result, &context);

    SHA1_Init(&context);

    SHA1_Update(&context, o_key_pad, HMAC_SHA1_BLOCKSIZE);
    SHA1_Update(&context, result, SHA_DIGEST_LENGTH);

    SHA1_Final(result, &context);

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(output + i * 2, 3, "%02x", result[i]);
    }

    fclose(fp);

    return 0;
}

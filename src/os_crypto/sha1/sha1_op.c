/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>

#include "sha1_op.h"
#include "headers/defs.h"
#include "shared.h"

/* OpenSSL SHA-1
 * Only use if OpenSSL is not available
#ifndef LIBOPENSSL_ENABLED
#include "sha.h"
#include "sha_locl.h"
#else
#include <openssl/sha.h>
#endif
*/

int OS_SHA1_File(const char *fname, os_sha1 output, int mode)
{
    SHA_CTX c;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md[SHA_DIGEST_LENGTH];
    size_t n;

    memset(output, 0, sizeof(os_sha1));
    buf[2049] = '\0';

    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    SHA1_Init(&c);
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        SHA1_Update(&c, buf, n);
    }

    SHA1_Final(&(md[0]), &c);

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    fclose(fp);

    return (0);
}

int OS_SHA1_Str(const char *str, ssize_t length, os_sha1 output)
{
    unsigned char md[SHA_DIGEST_LENGTH];
    size_t n;

    SHA_CTX c;
    SHA1_Init(&c);
    SHA1_Update(&c, (const unsigned char *)str, length < 0 ? (unsigned)strlen(str) : (unsigned)length);
    SHA1_Final(&(md[0]), &c);

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    return (0);
}

int OS_SHA1_Str2(const char *str, ssize_t length, os_sha1 output)
{
    unsigned char temp[SHA_DIGEST_LENGTH];
    size_t n;

    memset(temp, 0x0, SHA_DIGEST_LENGTH);
    SHA1((unsigned char *)str, length, temp);

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", temp[n]);
        output += 2;
    }

    return (0);
}

// Get the hexadecimal result of a SHA-1 digest

void OS_SHA1_Hexdigest(const unsigned char * digest, os_sha1 output) {
    size_t n;

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", digest[n]);
        output += 2;
    }
}

int OS_SHA1_File_Nbytes(const char *fname, SHA_CTX *c, os_sha1 output, int mode, int64_t nbytes) {

    FILE *fp = NULL;
    char buf[OS_MAXSTR];
    int64_t n;
    unsigned char md[SHA_DIGEST_LENGTH];

    memset(output, 0, sizeof(os_sha1));
    buf[OS_MAXSTR - 1] = '\0';

    /* It's important to read \r\n instead of \n to generate the correct hash */
#ifdef WIN32
    if (fp = w_fopen_r(fname, mode == OS_BINARY ? "rb" : "r"), fp == NULL) {
        return -1;
    }
#else
    if (fp = fopen(fname, mode == OS_BINARY ? "rb" : "r"), fp == NULL) {
        return -1;
    }
#endif

    SHA1_Init(c);

    for (int64_t bytes_count = 0; bytes_count < nbytes; bytes_count+=2048) {
        if(bytes_count+2048 < nbytes) {
            n = fread(buf, 1, 2048, fp);
        } else {
            n = fread(buf, 1, nbytes-bytes_count, fp);
        }

        buf[n] = '\0';
        SHA1_Update(c, buf, n);
    }

    SHA_CTX aux = *c;

    SHA1_Final(&(md[0]), &aux);

    OS_SHA1_Hexdigest(md, output);

    fclose(fp);

    return (0);
}

void OS_SHA1_Stream(SHA_CTX *c, os_sha1 output, char * buf) {
    if(buf) {
        size_t n = strlen(buf);

        SHA1_Update(c, buf, n);
    }

    if(output) {
        memset(output, 0, sizeof(os_sha1));
        unsigned char md[SHA_DIGEST_LENGTH];
        SHA_CTX aux = *c;

        SHA1_Final(&(md[0]), &aux);

        OS_SHA1_Hexdigest(md, output);
    }

}

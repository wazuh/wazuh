/* Copyright (C) 2015-2020, Wazuh Inc.
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

/* OpenSSL SHA-1
 * Only use if OpenSSL is not available
#ifndef LIBOPENSSL_ENABLED
#include "sha.h"
#include "sha_locl.h"
#else
#include <openssl/sha.h>
#endif
*/

#include <openssl/sha.h>


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

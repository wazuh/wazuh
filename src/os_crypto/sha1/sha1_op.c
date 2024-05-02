/* Copyright (C) 2015, Wazuh Inc.
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

int OS_SHA1_File(const char *fname, os_sha1 output, int mode) {
    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md[SHA_DIGEST_LENGTH];
    size_t n;

    memset(output, 0, sizeof(os_sha1));
    buf[2049] = '\0';

    fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        EVP_MD_CTX_free(sha1_ctx);
        return (-1);
    }

    EVP_DigestInit(sha1_ctx, EVP_sha1());
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        EVP_DigestUpdate(sha1_ctx, buf, n);
    }

    EVP_DigestFinal(sha1_ctx, md, NULL);

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    fclose(fp);
    EVP_MD_CTX_free(sha1_ctx);

    return (0);
}

int OS_SHA1_Str(const char *str, ssize_t length, os_sha1 output) {
    unsigned char md[SHA_DIGEST_LENGTH];
    size_t n;

    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestUpdate(sha1_ctx, (const unsigned char *)str, length < 0 ? (unsigned)strlen(str) : (unsigned)length);
    EVP_DigestFinal(sha1_ctx, md, NULL);

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    EVP_MD_CTX_free(sha1_ctx);

    return (0);
}

int OS_SHA1_Str2(const char *str, ssize_t length, os_sha1 output) {
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

int OS_SHA1_strings(os_sha1 output, ...) {
    unsigned char md[SHA_DIGEST_LENGTH];
    size_t n;
    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(sha1_ctx, EVP_sha1());

    va_list parameters;
    char* parameter = NULL;
    va_start(parameters, output);
    while (parameter = va_arg(parameters, char*), parameter) {
        EVP_DigestUpdate(sha1_ctx, parameter, strlen(parameter));
    }
    va_end(parameters);
    EVP_DigestFinal(sha1_ctx, md, NULL);

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    EVP_MD_CTX_free(sha1_ctx);

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

int OS_SHA1_File_Nbytes(const char *fname, EVP_MD_CTX **c, os_sha1 output, int mode, int64_t nbytes) {
    return OS_SHA1_File_Nbytes_with_fp_check(fname, c, output, mode, nbytes, 0);
}

#ifndef WIN32
int OS_SHA1_File_Nbytes_with_fp_check(const char * fname, EVP_MD_CTX ** c, os_sha1 output, int mode, int64_t nbytes,
                                      ino_t fd_check) {
#else
int OS_SHA1_File_Nbytes_with_fp_check(const char * fname, EVP_MD_CTX ** c, os_sha1 output, int mode, int64_t nbytes,
                                      DWORD fd_check) {
#endif

    FILE *fp = NULL;
    char buf[OS_MAXSTR];
    int64_t n;
    unsigned char md[SHA_DIGEST_LENGTH];

    if (c == NULL || *c == NULL) {
        mdebug1("Context for file '%s' can not be NULL.", fname);
        return -3;
    }

    memset(output, 0, sizeof(os_sha1));
    buf[OS_MAXSTR - 1] = '\0';

    EVP_DigestInit(*c, EVP_sha1());

    /* It's important to read \r\n instead of \n to generate the correct hash */
#ifdef WIN32
    BY_HANDLE_FILE_INFORMATION lpFileInformation;
    DWORD open_fd = 0;
    if (fp = w_fopen_r(fname, mode == OS_BINARY ? "rb" : "r", &lpFileInformation), fp == NULL) {
        return -1;
    } else {
        open_fd = lpFileInformation.nFileIndexLow + lpFileInformation.nFileIndexHigh;
    }
#else
    if (fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r"), fp == NULL) {
        return -1;
    }
#endif

    /* Check if it is the same file */
    if (fd_check != 0) {
#ifndef WIN32

        struct stat tmp_stat;

        if ((fstat(fileno(fp), &tmp_stat)) == -1) {
            merror(FSTAT_ERROR, fname, errno, strerror(errno));
        } else if (fd_check != tmp_stat.st_ino) {
            mdebug1("The inode does not belong to file '%s'. The hash of the file will be ignored.", fname);
            fclose(fp);
            return -2;
        }

#else
        if (open_fd != 0 && fd_check != open_fd) {
            mdebug1("The inode does not belong to file '%s'. The hash of the file will be ignored.", fname);
            fclose(fp);
            return -2;
        }

#endif
    }

    for (int64_t bytes_count = 0; bytes_count < nbytes; bytes_count+=2048) {
        if(bytes_count+2048 < nbytes) {
            n = fread(buf, 1, 2048, fp);
        } else {
            n = fread(buf, 1, nbytes-bytes_count, fp);
        }

        buf[n] = '\0';
        EVP_DigestUpdate(*c, buf, n);
    }

    EVP_MD_CTX *aux = EVP_MD_CTX_new();
    EVP_MD_CTX_copy(aux, *c);

    EVP_DigestFinal(aux, md, NULL);

    OS_SHA1_Hexdigest(md, output);

    EVP_MD_CTX_free(aux);

    fclose(fp);

    return (0);
}

void OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char * buf) {
    if(buf) {
        size_t n = strlen(buf);

        EVP_DigestUpdate(c, buf, n);
    }

    if(output) {
        memset(output, 0, sizeof(os_sha1));
        unsigned char md[SHA_DIGEST_LENGTH];
        EVP_MD_CTX *aux = EVP_MD_CTX_new();
        EVP_MD_CTX_copy(aux, c);

        EVP_DigestFinal(aux, md, NULL);
        OS_SHA1_Hexdigest(md, output);
        EVP_MD_CTX_free(aux);
    }

}

/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SHA1_OP_H
#define SHA1_OP_H

#include <sys/types.h>
#include <openssl/sha.h>
#ifdef WIN32
#include <winsock2.h>
#include <windef.h>
#endif
#include <openssl/evp.h>

#define OS_SHA1_HEXDIGEST_SIZE (SHA_DIGEST_LENGTH * 2) // Sha1 digest len (20) * 2 (hex chars per byte)

typedef char os_sha1[OS_SHA1_HEXDIGEST_SIZE + 1];

int OS_SHA1_File(const char *fname, os_sha1 output, int mode) __attribute((nonnull));
int OS_SHA1_Str(const char *str, ssize_t length, os_sha1 output) __attribute((nonnull));
int OS_SHA1_Str2(const char *str, ssize_t length, os_sha1 output) __attribute((nonnull));

/**
 * @brief Get the SHA-1 digest from a list of strings.
 *
 * @param output[out] Output string.
 * @param ...   [in] List of strings to calculate the SHA-1.
 */
int OS_SHA1_strings(os_sha1 output, ...);

/**
 * @brief Get the hexadecimal result of a SHA-1 digest
 *
 * @param digest[in] Binary SHA-1 digest.
 * @param output[out] Output string.
 */
void OS_SHA1_Hexdigest(const unsigned char * digest, os_sha1 output);

/**
 * @brief Calculates the SHA1 of a file until N byte and save the context
 * The context is not created, it is only reset, so the function that calls this function must previously do the creation of the context.
 * Saved context must be freed after use.
 *
 * @param fname[in] File name to calculate SHA1.
 * @param c[out] EVP_MD_CTX context.
 * @param output[out] Output string.
 * @param nbytes[in] Number of bytes to read.
 * @return 0 on success.
 * @return -1 when failure opening file.
 * @retval -2 When fp does not correspond to the `fname` file.
 * @retval -3 When context is NULL.
 */
int OS_SHA1_File_Nbytes(const char *fname, EVP_MD_CTX **c, os_sha1 output, int mode, int64_t nbytes);

/**
 * @brief If fp corresponds to fname then calculates the SHA1 of the `fname` file until N byte and save the context.
 * The context is not created, it is only reset, so the function that calls this function must previously do the creation of the context.
 * Saved context must be freed after use.
 *
 * @param[in] fname File name to calculate SHA1.
 * @param[out] c EVP_MD_CTX context.
 * @param[out] output Output string.
 * @param[in] nbytes Number of bytes to read.
 * @param[in] fd_check File serial number, Is checked against `fname`
 * @retval 0 on success
 * @retval -1 when failure opening file.
 * @retval -2 When fp does not correspond to the `fname` file.
 * @retval -3 When context is NULL.
 */
#ifndef WIN32
int OS_SHA1_File_Nbytes_with_fp_check(const char * fname, EVP_MD_CTX ** c, os_sha1 output, int mode, int64_t nbytes,
                                      ino_t fd_check);
#else
int OS_SHA1_File_Nbytes_with_fp_check(const char * fname, EVP_MD_CTX ** c, os_sha1 output, int mode, int64_t nbytes,
                                      DWORD fd_check);
#endif
/**
 * @brief update the context and calculates the SHA1, the context can not be null.
 *
 * @param c[out] EVP_MD_CTX context.
 * @param output[out] Output string.
 * @param buf[in] String to update the SHA1 context
 */
void OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char * buf);

#endif /* SHA1_OP_H */

/* Copyright (C) 2015-2021, Wazuh Inc.
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

typedef char os_sha1[41];

int OS_SHA1_File(const char *fname, os_sha1 output, int mode) __attribute((nonnull));
int OS_SHA1_Str(const char *str, ssize_t length, os_sha1 output) __attribute((nonnull));
int OS_SHA1_Str2(const char *str, ssize_t length, os_sha1 output) __attribute((nonnull));

/**
 * @brief Get the hexadecimal result of a SHA-1 digest
 *
 * @param digest[in] Binary SHA-1 digest.
 * @param output[out] Output string.
 */
void OS_SHA1_Hexdigest(const unsigned char * digest, os_sha1 output);

/**
 * @brief Calculates the SHA1 of a file until N byte and save the context
 *
 * @param fname[in] File name to calculate SHA1.
 * @param c[out] SHA1 context.
 * @param output[out] Output string.
 * @param nbytes[in] Number of bytes to read.
 * @return 0 on success, -1 when failure opening file.
 */
int OS_SHA1_File_Nbytes(const char *fname, SHA_CTX *c, os_sha1 output, int mode, int64_t nbytes);

/**
 * @brief update the context and calculates the SHA1
 *
 * @param c[out] SHA1 context.
 * @param output[out] Output string.
 * @param buf[in] String to update the SHA1 context
 */
void OS_SHA1_Stream(SHA_CTX *c, os_sha1 output, char * buf);

#endif /* SHA1_OP_H */

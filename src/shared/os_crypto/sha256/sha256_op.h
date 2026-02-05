/*
 * Copyright (C) 2015, Wazuh Inc.
 * Contributed by Arshad Khan (@arshad01)
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SHA256_OP_H
#define SHA256_OP_H

#include <sys/types.h>

typedef char os_sha256[65];

/**
 * @brief Calculates the SHA256 of a file.
 *
 * @param [in] fname Name of the file to calculate the hash.
 * @param [out] output Buffer where the hash will be written. Must be at least sizeof(os_sha256).
 * @param [in] mode Mode for opening the file. OS_BINARY or OS_TEXT.
 * @return 0 o success.
 */
int OS_SHA256_File(const char *fname, os_sha256 output, int mode) __attribute((nonnull));

/**
 * @brief Calculates the SHA256 of a string.
 *
 * @param [in] str String to calculate the SHA256.
 * @param [out] output Buffer where the hash will be written. Must be at least sizeof(os_sha256).
 * @return 0 o success.
 */
void OS_SHA256_String(const char *str, os_sha256 output);

/**
 * @brief Calculates the SHA256 of a string and chop the output in a specific size.
 *
 * @param [in] str String to calculate the SHA256.
 * @param [out] output Buffer where the hash will be written. Must be at least size+1 length.
 * @param [in] size Size to chop the calculated hash.
 * @return 0 o success.
 */
void OS_SHA256_String_sized(const char *str, char* output, size_t size);

#endif /* SHA256_OP_H */

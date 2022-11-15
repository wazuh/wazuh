/*
 * Cryptography
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 3, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#ifdef WIN32
#include <windows.h>

/**
 * @brief Verify the signature of a PE file.
 *
 * @param file_name PE file name.
 * @return ERROR_SUCCESS if the signature is valid, ERROR_INVALID_PARAMETER if the file is not a PE file,
 *         ERROR_FILE_NOT_FOUND if the file does not exist, or another error code.
 */
DWORD verify_pe_signature(const wchar_t *path);

/**
 * @brief Calculate the SHA256 hash of a file.
 *
 * @param path Path to the file.
 * @param hash Buffer to store the hash.
 * @param hash_size Size of the hash buffer.
 * @return int 0 on success otherwise error code.
 */
DWORD verify_hash_catalog(wchar_t *path);

/**
 * @brief Verify the signature of a file using the Windows Catalog.
 *
 * @param path Path to the file.
 * @return int 0 on success otherwise error code.
 */
DWORD get_file_hash(const wchar_t *path, BYTE **hash, DWORD *hash_size);

#endif
#endif


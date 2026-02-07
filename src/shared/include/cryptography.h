/*
 * Cryptography windows helper.
 * Copyright (C) 2015, Wazuh Inc.
 * November 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CRYPTOGRAPHY_H
#define _CRYPTOGRAPHY_H

#ifdef WIN32
#include <windows.h>
#include "os_err.h"

/**
 * @brief Verify the signature of a PE file.
 *
 * @param path PE file name.
 * @param error_message Pre-allocated buffer to store the error message.
 * @param error_message_size Size of the error_message buffer.
 * @return ERROR_SUCCESS if the signature is valid, ERROR_INVALID_PARAMETER if the file is not a PE file,
 *         ERROR_FILE_NOT_FOUND if the file does not exist, or another error code.
 */
DWORD verify_pe_signature(const wchar_t *path, char* error_message, int error_message_size);

/**
 * @brief Verify the signature of a file using the Windows Catalog.
 *
 * @param path Path to the file.
 * @param error_message Pre-allocated buffer to store the error message.
 * @param error_message_size Size of the error_message buffer.
 * @return int ERROR_SUCCESS on success otherwise error code.
 */
DWORD verify_hash_catalog(wchar_t *path, char* error_message, int error_message_size);

/**
 * @brief Calculate the SHA256 hash of a file.
 *
 * @param path Path to the file.
 * @param hash Buffer to store the hash.
 * @param hash_size Size of the hash buffer.
 * @param error_message Pre-allocated buffer to store the error message.
 * @param error_message_size Size of the error_message buffer.
 * @return int ERROR_SUCCESS on success otherwise error code.
 */
DWORD get_file_hash(const wchar_t *path, BYTE **hash, DWORD *hash_size, char* error_message, int error_message_size);

/**
 * @brief Verify the authenticity of a file by both its signature and hash. The file is not trusted if both method fail.
 *
 * @param file_path The path to the file to verify its auhtenticity.
 * @return w_err_t Returns OS_SUCCESS if at least one of the methods succeed, otherwise OS_INVALID.
 */
w_err_t verify_hash_and_pe_signature(wchar_t *file_path);

/**
 * @brief Check if the CA is available.
 *
 * @return DWORD ERROR_SUCCESS if the CA is available, otherwise error code.
 */
DWORD check_ca_available();

#endif // WIN32
#endif // _CRYPTOGRAPHY_H

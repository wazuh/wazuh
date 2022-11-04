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
/**
 * @brief Windows verification if the file is signed using WinVerifyTrust.
 * @param path Path to the file to verify.
 * @return 0 on success, 1 on error.
 */
int verify_pe_signature(const wchar_t *path);

/**
 * @brief Windows verification if the file is signed using Authenticode.
 * @param path Path to the file to verify.
 * @return 0 on success, 1 on error.
 */
int verify_catalog(const wchar_t *path);


#endif
#endif

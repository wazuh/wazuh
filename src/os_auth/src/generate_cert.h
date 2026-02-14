/*
 * Wazuh Certificate creation tool.
 *
 * Copyright (C) 2015, Wazuh Inc.
 * May 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "shared.h"


/**
 * @brief Function to generate a random serial number.
 *
 * @param sn ASN1_INTEGER to store the serial number. It cannot be NULL and it must be created using the
 *           ASN1_INTEGER_new() function.
 *
 * @return int 0 on success 1 on failure.
 */
int rand_serial(ASN1_INTEGER *sn);

/**
 * @brief Generates a OpenSSL new key.
 *
 * @param bits Key size.
 * @return Pointer to a EVP_PKEY structure.
 */
EVP_PKEY* generate_key(int bits);

/**
 * @brief Generates a self-signed X509 certificate.
 *
 * @param days Certificate's validity (days).
 * @param bits Number of bits for the key.
 * @param key_path Path to store the key to sign the certificate.
 * @param cert_path Path to store the certificate.
 * @param sub Subject for the certificate.
 * @return 0 on success 1 on failure
 */
int generate_cert(unsigned long days, unsigned long bits, const char *key_path, const char *cert_path, const char* sub);

/**
 * @brief Function to add X509v3 extensions to the certificate.
 *
 * @param cert Pointer to a valid certificate.
 * @param ctx Pointer to a X509v3 context.
 * @param ext_nid NID.
 * @param value Value to use in the extension.
 */
void add_x509_ext(X509 *cert, X509V3_CTX *ctx, int ext_nid, const char *value);

/**
 * @brief Dump the certificates to disk.
 *
 * @param key Pointer to a valid key.
 * @param x509 Pointer to a valid X509 certificate.
 * @param key_name Path to store the key.
 * @param cert_name Pat to store the certificate.
 */
int dump_key_cert(EVP_PKEY* key, X509* x509, const char* key_name, const char* cert_name);

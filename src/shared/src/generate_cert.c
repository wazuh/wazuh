/*
 * Wazuh Certificate creation.
 *
 * Copyright (C) 2015, Wazuh Inc.
 * May 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "generate_cert.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

EVP_PKEY* generate_key(int bits) {
    EVP_PKEY* key = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (key == NULL || ctx == NULL) {
        merror("Cannot create EVP_PKEY or EVP_PKEY_CTX structure.");
        goto error;
    }

    // Initialize the RSA key generation parameters
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        merror("Cannot initialize RSA key generation parameters.");
        goto error;
    }

    // Generate the RSA key pair
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        merror("Cannot generate RSA key pair.");
        goto error;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;

error:
    if (key) {
        EVP_PKEY_free(key);
    }

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return NULL;
}


/**
 * @brief Generates a self-signed X509 certificate.
 *
 * @param key Key that will be used to sign the certificate.
 * @return 1 on failure 0 on success.
 */
int generate_cert(unsigned long days,
                  unsigned long bits,
                  const char *key_path,
                  const char *cert_path,
                  const char* subj) {
    X509* cert = X509_new();
    X509_NAME* name = NULL;
    X509V3_CTX ctx;
    EVP_PKEY* key = generate_key(bits);
    ASN1_INTEGER* serial_number = ASN1_INTEGER_new();
    char **split_subj = NULL;

    if (key == NULL) {
        merror("Cannot generate key to sign the certificate.");
        goto error;
    }

    if(cert == NULL) {
        merror("Cannot generate certificate.");
        goto error;
    }

    if (serial_number == NULL) {
        merror("Cannot allocate serial number."); // LCOV_EXCL_LINE
        goto error; // LCOV_EXCL_LINE
    }

    // Assign a random serial number to the certificate
    if (rand_serial(serial_number) == 1) {
        merror("Cannot generate serial number."); // LCOV_EXCL_LINE
        goto error; // LCOV_EXCL_LINE
    }

    X509_set_version(cert, 2);
    X509_set_serialNumber(cert, serial_number);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days * 86400UL);

    X509_set_pubkey(cert, key);

    name = X509_get_subject_name(cert);
    split_subj = w_string_split(subj, "/", 0);

    for (int i = 0; split_subj[i]; i++) {
        char *delim = wstr_chr(split_subj[i], '=');
        if (delim == NULL || *(delim + 1) == '\0') {
            continue;
        }

        *delim = '\0';

        X509_NAME_add_entry_by_txt(name, split_subj[i],  MBSTRING_ASC, (unsigned char*) delim + 1, -1, -1, 0);
    }

    X509_set_issuer_name(cert, name);
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    add_x509_ext(cert, &ctx, NID_subject_key_identifier, "hash");
    add_x509_ext(cert, &ctx, NID_authority_key_identifier, "keyid");
    add_x509_ext(cert, &ctx, NID_basic_constraints, "critical,CA:TRUE");

    if(!X509_sign(cert, key, EVP_sha256())) {
        merror("Error signing certificate.");
        goto error;
    }

    if (dump_key_cert(key, cert, key_path, cert_path)) {
        goto error;
    }

    X509_free(cert);
    EVP_PKEY_free(key);
    ASN1_INTEGER_free(serial_number);
    free_strarray(split_subj);
    return 0;

error:

    X509_free(cert);
    ASN1_INTEGER_free(serial_number);
    free_strarray(split_subj);
    EVP_PKEY_free(key);

    return 1;
}

void add_x509_ext(X509* cert, X509V3_CTX *ctx, int ext_nid, const char *value) {
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, ext_nid, value);

    X509_add_ext(cert, ex, -1);

    X509_EXTENSION_free(ex);
}

int dump_key_cert(EVP_PKEY* key, X509* x509, const char* key_name, const char* cert_name) {
    FILE* key_file = wfopen(key_name, "wb");

    if(!key_file)
    {
        merror("Cannot open %s.", key_name);
        return 1;
    }

    if(!PEM_write_PrivateKey(key_file, key, NULL, NULL, 0, NULL, NULL))
    {
        merror("Cannot dump private key.");
        fclose(key_file);
        return 1;
    }

    fclose(key_file);

    FILE* x509_file = wfopen(cert_name, "wb");
    if(!x509_file)
    {
        merror("Cannot open %s.", cert_name);
        return 1;
    }

    if(!PEM_write_X509(x509_file, x509))
    {
        merror("Cannot dump certificate.");
        fclose(x509_file);
        return 1;
    }

    fclose(x509_file);

    return 0;
}


int rand_serial(ASN1_INTEGER *sn) {
    BIGNUM* bn = BN_new();

    if (sn == NULL) {
        return 1; // LCOV_EXCL_LINE
    }

    if (bn == NULL) {
        return 1; // LCOV_EXCL_LINE
    }

    /*
    * The 159 constant is defined in openssl/apps/apps.h (SERIAL_RAND_BITS)
    * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
    * so that the first bit will never be one, so that the DER encoding
    * rules won't force a leading octet.
    */
    if (!BN_rand(bn, 159, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        return 1; // LCOV_EXCL_LINE
    }

    if (!BN_to_ASN1_INTEGER(bn, sn)) {
        BN_free(bn); // LCOV_EXCL_LINE
        return 1; // LCOV_EXCL_LINE
    }

    BN_free(bn);

    return 0;
}

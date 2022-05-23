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

#include <cstdio>
#include <iostream>
#include <memory>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 * @brief Smart deleter used to free diferent structures.
 *
 */
struct smartDeleter final
{
    void operator()(EVP_PKEY* key)
    {
        EVP_PKEY_free(key);
    }

    void operator()(X509* cert)
    {
        X509_free(cert);
    }

    void operator()(BIGNUM* bn)
    {
        BN_free(bn);
    }
};

/**
 * @brief Generates a OpenSSL new key.
 *
 * @param bits Key size. Defaults to 2048.
 * @return EVP_PKEY structure.
 */
std::unique_ptr<EVP_PKEY, smartDeleter> generate_key(int bits = 2048);

/**
 * @brief Generates a self-signed X509 certificate.
 *
 * @param key Key that will be used to sign the certificate.
 * @return X509 structure.
 */
std::unique_ptr<X509, smartDeleter> generate_cert(const std::unique_ptr<EVP_PKEY, smartDeleter>& key);

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
 * @param key Smart pointer to a valid key.
 * @param x509 Smart pointer to a valid X509 certificate.
 * @param key_name Path to store the key.
 * @param cert_name Pat to store the certificate.
 * @return true In case of success.
 * @return false In case of failure.
 */
bool dump_key_cert(const std::unique_ptr<EVP_PKEY, smartDeleter>& key,
                   const std::unique_ptr<X509, smartDeleter>& x509,
                   const std::string& key_name,
                   const std::string& cert_name);


int main(int argc, char ** argv)
{

    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <manager_key_path> <manager_cert_path>" << std::endl;
        return 1;
    }

    const auto key_name { argv[1] };
    const auto cert_name { argv[2] };

    /* Generate the key. */
    std::cout << "Generating RSA key..." << std::endl;

    auto pkey = generate_key();

    if(pkey == nullptr)
    {
        return 1;
    }

    /* Generate the certificate. */
    std::cout << "Generating x509 certificate..." << std::endl;

    auto x509 = generate_cert(pkey);

    if(x509 == nullptr)
    {
        return 1;
    }

    /* Write the private key and certificate out to disk. */
    std::cout << "Writing key and certificate to disk..." << std::endl;

    if (dump_key_cert(pkey, x509, key_name, cert_name)) {
        std::cout << "Successfuly created key and certificate." << std::endl;
        return 0;
    }

    return 1;
}

std::unique_ptr<EVP_PKEY, smartDeleter> generate_key(int bits)
{
    std::unique_ptr<EVP_PKEY, smartDeleter> key(EVP_PKEY_new());
    std::unique_ptr<BIGNUM, smartDeleter> bn(BN_new());
    RSA* rsa = RSA_new(); // This structure is free'd after EVP_PKEY_assign_RSA.

    if(key.get() == NULL)
    {
        std::cerr << "Cannot create EVP_PKEY structure." << std::endl;
        return nullptr;
    }

    if (bn.get() == NULL)
    {
        std::cerr << "Cannot create BN structure." << std::endl;
        return nullptr;
    }
    if (rsa == NULL)
    {
        std::cerr << "Cannot create RSA structure." << std::endl;
        return nullptr;
    }

    BN_set_word(bn.get(), RSA_F4);
    RSA_generate_key_ex(rsa, bits, bn.get(), NULL);

    if(!EVP_PKEY_assign_RSA(key.get(), rsa))
    {
        std::cerr << "Cannot generate RSA key." << std::endl;
        RSA_free(rsa);
        return nullptr;
    }

    return key;
}

/**
 * @brief Generates a self-signed X509 certificate.
 *
 * @param key Key that will be used to sign the certificate.
 * @return X509 structure.
 */
std::unique_ptr<X509, smartDeleter> generate_cert(const std::unique_ptr<EVP_PKEY, smartDeleter>& key)
{
    std::unique_ptr<X509, smartDeleter> cert (X509_new());
    X509_NAME* name = NULL;
    X509V3_CTX ctx;

    if(cert.get() == NULL)
    {
        std::cerr << "Cannot create X509 structure." << std::endl;
        return nullptr;
    }

    X509_set_version(cert.get(), 2);

    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 31536000L);

    X509_set_pubkey(cert.get(), key.get());

    name = X509_get_subject_name(cert.get());

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)  "US"         , -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *) "California" , -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)  "Wazuh"      , -1, -1, 0);

    X509_set_issuer_name(cert.get(), name);
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), NULL, NULL, 0);

    add_x509_ext(cert.get(), &ctx, NID_subject_key_identifier, "hash");
    add_x509_ext(cert.get(), &ctx, NID_authority_key_identifier, "keyid");
    add_x509_ext(cert.get(), &ctx, NID_basic_constraints, "critical,CA:TRUE");

    if(!X509_sign(cert.get(), key.get(), EVP_sha256()))
    {
        std::cerr << "Error signing certificate." << std::endl;
        return nullptr;
    }

    return cert;
}

void add_x509_ext(X509* cert, X509V3_CTX *ctx, int ext_nid, const char *value)
{
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, ext_nid, value);

    X509_add_ext(cert, ex, -1);

    X509_EXTENSION_free(ex);
}

bool dump_key_cert(const std::unique_ptr<EVP_PKEY, smartDeleter>& key,
                   const std::unique_ptr<X509, smartDeleter>& x509,
                   const std::string& key_name,
                   const std::string& cert_name)
{
    /* Open the PEM file for writing the key to disk. */
    FILE* key_file = fopen(key_name.c_str(), "wb");
    if(!key_file)
    {
        std::cerr << "Cannot open " << key_name << "." << std::endl;
        return false;
    }

    bool ret = PEM_write_PrivateKey(key_file, key.get(), NULL, NULL, 0, NULL, NULL);
    fclose(key_file);

    if(!ret)
    {
        std::cerr << "Cannot dump private key." << std::endl;
        return false;
    }

    FILE* x509_file = fopen(cert_name.c_str(), "wb");
    if(!x509_file)
    {
        std::cerr << "Cannot open " << cert_name << "." << std::endl;
        return false;
    }

    /* Write the certificate to disk. */
    ret = PEM_write_X509(x509_file, x509.get());
    fclose(x509_file);

    if(!ret)
    {
        std::cerr << "Cannot dump certificate." << std::endl;
        return false;
    }

    return true;
}

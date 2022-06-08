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

    void operator()(ASN1_INTEGER* asn1)
    {
        ASN1_INTEGER_free(asn1);
    }
};


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
 * @param bits Key size. Defaults to 2048.
 * @return Smart pointer to a EVP_PKEY structure.
 */
std::unique_ptr<EVP_PKEY, smartDeleter> generate_key(int bits = 2048);

/**
 * @brief Generates a self-signed X509 certificate.
 *
 * @param key Key that will be used to sign the certificate.
 * @return Amart pointer to a x509 structure.
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
 */
int dump_key_cert(const std::unique_ptr<EVP_PKEY, smartDeleter>& key,
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

    std::cout << "Generating RSA key..." << std::endl;
    auto pkey = generate_key();

    if(pkey == nullptr)
    {
        return 1;
    }

    std::cout << "Generating x509 certificate..." << std::endl;
    auto x509 = generate_cert(pkey);

    if(x509 == nullptr)
    {
        return 1;
    }

    std::cout << "Writing key and certificate to disk..." << std::endl;
    if (dump_key_cert(pkey, x509, key_name, cert_name)) {
        std::cerr << "Cannot dump key and certificate into disk." << std::endl;
        return 1;
    }

    std::cout << "Successfuly created key and certificate." << std::endl;
    return 0;
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
    std::unique_ptr<X509, smartDeleter> cert(X509_new());
    std::unique_ptr<ASN1_INTEGER, smartDeleter> serial_number(ASN1_INTEGER_new());
    X509_NAME* name = NULL;
    X509V3_CTX ctx;

    if(cert.get() == NULL)
    {
        std::cerr << "Cannot create X509 structure." << std::endl;
        return nullptr;
    }

    if (serial_number.get() == NULL)
    {
        std::cerr << "Cannot create serial number." << std::endl;
        return nullptr;
    }

    // Assign a random serial number to the certificate
    if (rand_serial(serial_number.get()) == 1)
    {
        std::cerr << "Cannot generate serial number." << std::endl;
        return nullptr;
    }

    X509_set_version(cert.get(), 2);
    X509_set_serialNumber(cert.get(), serial_number.get());
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

int dump_key_cert(const std::unique_ptr<EVP_PKEY, smartDeleter>& key,
                   const std::unique_ptr<X509, smartDeleter>& x509,
                   const std::string& key_name,
                   const std::string& cert_name)
{
    FILE* key_file = fopen(key_name.c_str(), "wb");

    if(!key_file)
    {
        std::cerr << "Cannot open " << key_name << "." << std::endl;
        return 1;
    }

    if(!PEM_write_PrivateKey(key_file, key.get(), NULL, NULL, 0, NULL, NULL))
    {
        std::cerr << "Cannot dump private key." << std::endl;
        fclose(key_file);

        return 1;
    }

    FILE* x509_file = fopen(cert_name.c_str(), "wb");
    if(!x509_file)
    {
        std::cerr << "Cannot open " << cert_name << "." << std::endl;
        return 1;
    }

    if(!PEM_write_X509(x509_file, x509.get()))
    {
        std::cerr << "Cannot dump certificate." << std::endl;
        fclose(x509_file);

        return 1;
    }

    fclose(key_file);
    fclose(x509_file);

    return 0;
}


int rand_serial(ASN1_INTEGER *sn)
{
    std::unique_ptr<BIGNUM, smartDeleter> bn(BN_new());
    if (bn.get() == NULL)
    {
        return 0;
    }

    /*
    * The 159 constant is defined in openssl/apps/apps.h (SERIAL_RAND_BITS)
    * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
    * so that the first bit will never be one, so that the DER encoding
    * rules won't force a leading octet.
    */
    if (!BN_rand(bn.get(), 159, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        return 1;
    }

    if (sn && !BN_to_ASN1_INTEGER(bn.get(), sn))
    {
        BN_free(bn.get());
        return 1;

    }

    return 0;
}

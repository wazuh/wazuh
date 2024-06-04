/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 05, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OPENSSL_PRIMITIVES_HPP
#define _OPENSSL_PRIMITIVES_HPP

#include <openssl/pem.h>
#include <openssl/rsa.h>

class OpenSSLPrimitives
{
protected:
    OpenSSLPrimitives() = default;
    virtual ~OpenSSLPrimitives() = default;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    inline int RSA_size(const RSA* rsa)
    {
        return ::RSA_size(rsa);
    }

    inline void RSA_free(RSA* r)
    {
        return ::RSA_free(r);
    }

    inline int RSA_public_encrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
    {
        return ::RSA_public_encrypt(flen, from, to, rsa, padding);
    }

    inline int RSA_private_decrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
    {
        return ::RSA_private_decrypt(flen, from, to, rsa, padding);
    }

    inline RSA* PEM_read_RSAPrivateKey(FILE* out, RSA** x, pem_password_cb* cb, void* u)
    {
        return ::PEM_read_RSAPrivateKey(out, x, cb, u);
    }

    inline RSA* PEM_read_RSA_PUBKEY(FILE* out, RSA** x, pem_password_cb* cb, void* u)
    {
        return ::PEM_read_RSA_PUBKEY(out, x, cb, u);
    }

    inline X509* PEM_read_X509(FILE* out, X509** x, pem_password_cb* cb, void* u)
    {
        return ::PEM_read_X509(out, x, cb, u);
    }

    inline void X509_free(X509* a)
    {
        return ::X509_free(a);
    }

    inline EVP_PKEY* X509_get_pubkey(X509* x)
    {
        return ::X509_get_pubkey(x);
    }

    inline void EVP_PKEY_free(EVP_PKEY* pkey)
    {
        return ::EVP_PKEY_free(pkey);
    }

    inline rsa_st* EVP_PKEY_get1_RSA(EVP_PKEY* pkey)
    {
        return ::EVP_PKEY_get1_RSA(pkey);
    }

    inline int EVP_PKEY_get_base_id(const EVP_PKEY* pkey)
    {
        return ::EVP_PKEY_get_base_id(pkey);
    }
#pragma GCC diagnostic pop
};

#endif // OPENSSL_PRIMITIVES_HPP

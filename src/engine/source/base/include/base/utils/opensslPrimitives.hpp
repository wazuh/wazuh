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

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace base::utils
{
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

    inline int RAND_bytes(unsigned char* buf, int num)
    {
        return ::RAND_bytes(buf, num);
    }

    inline EVP_CIPHER_CTX* EVP_CIPHER_CTX_new()
    {
        return ::EVP_CIPHER_CTX_new();
    }

    inline void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx)
    {
        return ::EVP_CIPHER_CTX_free(ctx);
    }

    inline const EVP_CIPHER* EVP_aes_256_cbc()
    {
        return ::EVP_aes_256_cbc();
    }

    inline int EVP_EncryptInit_ex(
        EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)
    {
        return ::EVP_EncryptInit_ex(ctx, type, impl, key, iv);
    }

    inline int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)
    {
        return ::EVP_EncryptUpdate(ctx, out, outl, in, inl);
    }

    inline int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl)
    {
        return ::EVP_EncryptFinal_ex(ctx, out, outl);
    }

    inline int EVP_DecryptInit_ex(
        EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)
    {
        return ::EVP_DecryptInit_ex(ctx, type, impl, key, iv);
    }

    inline int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)
    {
        return ::EVP_DecryptUpdate(ctx, out, outl, in, inl);
    }

    inline int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)
    {
        return ::EVP_DecryptFinal_ex(ctx, outm, outl);
    }

    const int AES_BLOCK_LENGTH = AES_BLOCK_SIZE;

    inline unsigned long ERR_get_error(void)
    {
        return ::ERR_get_error();
    }

    inline const char* ERR_reason_error_string(unsigned long e)
    {
        return ::ERR_reason_error_string(e);
    }
#pragma GCC diagnostic pop
};

} // namespace base::utils

#endif // OPENSSL_PRIMITIVES_HPP

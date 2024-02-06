/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Febrary 6, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opensslWrapper_test.hpp"
#include "opensslWrapper.hpp"
#include <gmock/gmock.h>

void OpenSSLWrapperTest::SetUp() {};
void OpenSSLWrapperTest::TearDown() {};

using testing::_;
// using testing::DoAll;
// using testing::Invoke;
using testing::Return;
// using testing::SetArgPointee;
// using testing::SetArrayArgument;

class OpenSSLPrimitivesWrapper
{
public:
    OpenSSLPrimitivesWrapper() = default;
    ~OpenSSLPrimitivesWrapper() = default;

    MOCK_METHOD(int, RSA_size,(const RSA *rsa));
    MOCK_METHOD(void, RSA_free, (RSA *r));
    MOCK_METHOD(int, RSA_public_encrypt, (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding));
    MOCK_METHOD(int, RSA_private_decrypt, (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding));
    MOCK_METHOD(RSA*, PEM_read_RSAPrivateKey, (FILE *out, RSA **x, pem_password_cb *cb, void *u));
    MOCK_METHOD(RSA*, PEM_read_RSA_PUBKEY, (FILE *out, RSA **x, pem_password_cb *cb, void *u));
    MOCK_METHOD(X509*, PEM_read_X509, (FILE *out, X509 **x, pem_password_cb *cb, void *u));
    MOCK_METHOD(void, X509_free, (X509 *a));
    MOCK_METHOD(EVP_PKEY*, X509_get_pubkey, (X509 *x));
    MOCK_METHOD(void, EVP_PKEY_free, (EVP_PKEY *pkey));
    MOCK_METHOD(rsa_st*, EVP_PKEY_get1_RSA, (EVP_PKEY *pkey));
};

class OSPrimitivesWrapper
{
public:
    OSPrimitivesWrapper() = default;
    ~OSPrimitivesWrapper() = default;

    MOCK_METHOD(FILE*, fopen, (const char * filename, const char * mode));
    MOCK_METHOD(int, fclose, (FILE* stream));
};

TEST_F(OpenSSLWrapperTest, OpenSSLWrapperTestInstance)
{
    OpenSSL<OpenSSLPrimitivesWrapper, OSPrimitivesWrapper> opensslWrapper;
}

TEST_F(OpenSSLWrapperTest, getPubKeyFromCertMissingCertficate)
{
    OpenSSL<OpenSSLPrimitivesWrapper, OSPrimitivesWrapper> opensslWrapper;

    EXPECT_CALL(opensslWrapper, PEM_read_X509(_, _, _, _)).WillOnce(Return(nullptr));

    RSA* p {nullptr};
    EXPECT_ANY_THROW({ opensslWrapper.getPubKeyFromCert(p, nullptr); });
}

TEST_F(OpenSSLWrapperTest, createRSAInvalidRSAFile)
{
    OpenSSL<OpenSSLPrimitivesWrapper, OSPrimitivesWrapper> opensslWrapper;

    EXPECT_CALL(opensslWrapper, fopen(_, _)).WillOnce(Return(nullptr));

    RSA* p {nullptr};
    try
    {
        opensslWrapper.createRSA(p, "keyfilePath", RSA_PRIVATE);
        FAIL();
    }
    catch(const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Failed to open RSA file: keyfilePath");
    }
}

TEST_F(OpenSSLWrapperTest, createRSAInvalidPrivateKey)
{
    OpenSSL<OpenSSLPrimitivesWrapper, OSPrimitivesWrapper> opensslWrapper;

    EXPECT_CALL(opensslWrapper, fopen(_, _)).WillOnce(Return((FILE*)1));
    EXPECT_CALL(opensslWrapper, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(opensslWrapper, PEM_read_RSAPrivateKey(_, _, _, _)).WillOnce(Return(nullptr));

    RSA* p {nullptr};
    try
    {
        opensslWrapper.createRSA(p, "keyfilePath", RSA_PRIVATE);
        FAIL();
    }
    catch(const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error reading RSA private key");
    }
}

TEST_F(OpenSSLWrapperTest, createRSAInvalidPublicKey)
{
    OpenSSL<OpenSSLPrimitivesWrapper, OSPrimitivesWrapper> opensslWrapper;

    EXPECT_CALL(opensslWrapper, fopen(_, _)).WillOnce(Return((FILE*)1));
    EXPECT_CALL(opensslWrapper, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(opensslWrapper, PEM_read_RSA_PUBKEY(_, _, _, _)).WillOnce(Return(nullptr));

    RSA* p {nullptr};
    try
    {
        opensslWrapper.createRSA(p, "keyfilePath", RSA_PUBLIC);
        FAIL();
    }
    catch(const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error reading RSA public key");
    }
}

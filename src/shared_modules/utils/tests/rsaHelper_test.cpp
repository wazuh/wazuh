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

#include "rsaHelper_test.hpp"
#include "rsaHelper.hpp"
#include <gmock/gmock.h>

using testing::_;
using testing::Return;
using testing::ReturnNull;
using testing::StrEq;

constexpr auto KEYFILE {"keyfilePath"};
constexpr auto KEY {"AbCd1234"};

void RSAHelperTest::SetUp() {};
void RSAHelperTest::TearDown() {};

class RSAWrapper
{
public:
    RSAWrapper() = default;
    ~RSAWrapper() = default;

    MOCK_METHOD(int, RSA_size, (const RSA* rsa));
    MOCK_METHOD(void, RSA_free, (RSA * r));
    MOCK_METHOD(int,
                RSA_public_encrypt,
                (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding));
    MOCK_METHOD(int,
                RSA_private_decrypt,
                (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding));
    MOCK_METHOD(RSA*, PEM_read_RSAPrivateKey, (FILE * out, RSA** x, pem_password_cb* cb, void* u));
    MOCK_METHOD(RSA*, PEM_read_RSA_PUBKEY, (FILE * out, RSA** x, pem_password_cb* cb, void* u));
    MOCK_METHOD(X509*, PEM_read_X509, (FILE * out, X509** x, pem_password_cb* cb, void* u));
    MOCK_METHOD(void, X509_free, (X509 * a));
    MOCK_METHOD(EVP_PKEY*, X509_get_pubkey, (X509 * x));
    MOCK_METHOD(void, EVP_PKEY_free, (EVP_PKEY * pkey));
    MOCK_METHOD(rsa_st*, EVP_PKEY_get1_RSA, (EVP_PKEY * pkey));
    MOCK_METHOD(int, EVP_PKEY_get_base_id, (const EVP_PKEY* pkey));
};

class OSPrimitivesWrapper
{
public:
    OSPrimitivesWrapper() = default;
    ~OSPrimitivesWrapper() = default;

    MOCK_METHOD(FILE*, fopen, (const char* filename, const char* mode));
    MOCK_METHOD(int, fclose, (FILE * stream));
};

TEST_F(RSAHelperTest, TestInstance)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;
}

TEST_F(RSAHelperTest, getPubKeyFromCertMissingCertficate)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_X509((FILE*)1, NULL, NULL, NULL)).WillOnce(ReturnNull());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output, true);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error reading X.509 certificate");
    }
}

TEST_F(RSAHelperTest, getPubKeyFromCertMissingPublicKey)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_X509((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((X509*)2));
    EXPECT_CALL(rsaHelper, X509_get_pubkey((X509*)2)).WillOnce(ReturnNull());
    EXPECT_CALL(rsaHelper, X509_free((X509*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output, true);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error reading public key");
    }
}

TEST_F(RSAHelperTest, createRSAInvalidRSAFile)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(ReturnNull());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), std::string("Failed to open RSA file: ").append(KEYFILE).c_str());
    }
}

TEST_F(RSAHelperTest, createRSAInvalidPrivateKey)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSAPrivateKey((FILE*)1, NULL, NULL, NULL)).WillOnce(ReturnNull());

    try
    {
        std::string output;
        rsaHelper.rsaDecrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error reading RSA private key");
    }
}

TEST_F(RSAHelperTest, createRSAInvalidPublicKey)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSA_PUBKEY((FILE*)1, NULL, NULL, NULL)).WillOnce(ReturnNull());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error reading RSA public key");
    }
}

TEST_F(RSAHelperTest, rsaEncryptFailed)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSA_PUBKEY((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_public_encrypt(strlen(KEY), _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(-1));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "RSA encryption failed");
    }
}

TEST_F(RSAHelperTest, rsaEncryptRSACertUnsuportedType)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_X509((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((X509*)2));
    EXPECT_CALL(rsaHelper, X509_get_pubkey((X509*)2)).WillOnce(Return((EVP_PKEY*)3));
    EXPECT_CALL(rsaHelper, EVP_PKEY_get_base_id(_)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, EVP_PKEY_free((EVP_PKEY*)3)).WillOnce(Return());
    EXPECT_CALL(rsaHelper, X509_free((X509*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output, true);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Unsupported key type");
    }
}

TEST_F(RSAHelperTest, rsaEncryptRSACertErrorExtracting)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_X509((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((X509*)2));
    EXPECT_CALL(rsaHelper, X509_get_pubkey((X509*)2)).WillOnce(Return((EVP_PKEY*)3));
    EXPECT_CALL(rsaHelper, EVP_PKEY_get_base_id(_)).WillOnce(Return(EVP_PKEY_RSA));
    EXPECT_CALL(rsaHelper, EVP_PKEY_get1_RSA(_)).WillOnce(Return((rsa_st*)0));
    EXPECT_CALL(rsaHelper, EVP_PKEY_free((EVP_PKEY*)3)).WillOnce(Return());
    EXPECT_CALL(rsaHelper, X509_free((X509*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output, true);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "Error extracting RSA public key from EVP_PKEY");
    }
}

TEST_F(RSAHelperTest, rsaEncryptRSAPublicSucces)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSA_PUBKEY((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_public_encrypt(strlen(KEY), _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    std::string output;
    EXPECT_NO_THROW({ rsaHelper.rsaEncrypt(KEYFILE, KEY, output); });
}

TEST_F(RSAHelperTest, rsaEncryptRSACertSucces)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_X509((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((X509*)2));
    EXPECT_CALL(rsaHelper, X509_get_pubkey((X509*)2)).WillOnce(Return((EVP_PKEY*)3));
    EXPECT_CALL(rsaHelper, EVP_PKEY_get_base_id(_)).WillOnce(Return(EVP_PKEY_RSA));
    EXPECT_CALL(rsaHelper, EVP_PKEY_get1_RSA(_)).WillOnce(Return((rsa_st*)4));
    EXPECT_CALL(rsaHelper, EVP_PKEY_free((EVP_PKEY*)3)).WillOnce(Return());
    EXPECT_CALL(rsaHelper, X509_free((X509*)2)).WillOnce(Return());
    EXPECT_CALL(rsaHelper, RSA_size((rsa_st*)4)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_public_encrypt(strlen(KEY), _, _, (rsa_st*)4, RSA_PKCS1_PADDING)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, RSA_free((rsa_st*)4)).WillOnce(Return());

    std::string output;
    EXPECT_NO_THROW({ rsaHelper.rsaEncrypt(KEYFILE, KEY, output, true); });
}

TEST_F(RSAHelperTest, rsaDecryptDecryptionFailed)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSAPrivateKey((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_private_decrypt(256, _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(-1));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaDecrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "RSA decryption failed");
    }
}

TEST_F(RSAHelperTest, rsaDecryptSuccess)
{
    RSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSAPrivateKey((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_private_decrypt(256, _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    std::string output;
    EXPECT_NO_THROW({ rsaHelper.rsaDecrypt(KEYFILE, KEY, output); });
}

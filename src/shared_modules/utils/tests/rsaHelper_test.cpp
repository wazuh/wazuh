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
    MOCK_METHOD(unsigned long, ERR_get_error, ());
    MOCK_METHOD(const char*, ERR_reason_error_string, (unsigned long));
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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;
}

TEST_F(RSAHelperTest, getPubKeyFromCertMissingCertficate)
{
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSA_PUBKEY((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_public_encrypt(strlen(KEY), _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(-1));
    EXPECT_CALL(rsaHelper, ERR_get_error()).WillOnce(Return(1));
    EXPECT_CALL(rsaHelper, ERR_reason_error_string((unsigned long)1)).WillOnce(Return("Reported internal error"));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaEncrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "RSA encryption failed: Reported internal error");
    }
}

TEST_F(RSAHelperTest, rsaEncryptRSACertUnsuportedType)
{
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

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
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSAPrivateKey((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_private_decrypt(strlen(KEY), _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(-1));
    EXPECT_CALL(rsaHelper, ERR_get_error()).WillOnce(Return(1));
    EXPECT_CALL(rsaHelper, ERR_reason_error_string((unsigned long)1)).WillOnce(Return("Reported internal error"));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    try
    {
        std::string output;
        rsaHelper.rsaDecrypt(KEYFILE, KEY, output);
        FAIL();
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), "RSA decryption failed: Reported internal error");
    }
}

TEST_F(RSAHelperTest, rsaDecryptSuccess)
{
    TRSAHelper<RSAWrapper, OSPrimitivesWrapper> rsaHelper;

    EXPECT_CALL(rsaHelper, fopen(StrEq(KEYFILE), "r")).WillOnce(Return((FILE*)1));
    EXPECT_CALL(rsaHelper, fclose((FILE*)1)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, PEM_read_RSAPrivateKey((FILE*)1, NULL, NULL, NULL)).WillOnce(Return((RSA*)2));
    EXPECT_CALL(rsaHelper, RSA_size((RSA*)2)).WillOnce(Return(strlen(KEY)));
    EXPECT_CALL(rsaHelper, RSA_private_decrypt(strlen(KEY), _, _, (RSA*)2, RSA_PKCS1_PADDING)).WillOnce(Return(0));
    EXPECT_CALL(rsaHelper, RSA_free((RSA*)2)).WillOnce(Return());

    std::string output;
    EXPECT_NO_THROW({ rsaHelper.rsaDecrypt(KEYFILE, KEY, output); });
}

TEST_P(RSAHelperTest2, test)
{
    RSAHelper rsaHelper;
    const std::string plainText {"plain-text"};

    auto pair = GetParam();

    std::string encryptedValue;
    EXPECT_NO_THROW(rsaHelper.rsaEncrypt(pair.first.c_str(), plainText, encryptedValue, true));
    std::string decryptedValue;
    EXPECT_NO_THROW(rsaHelper.rsaDecrypt(pair.second.c_str(), encryptedValue, decryptedValue));

    EXPECT_EQ(plainText, decryptedValue);
}

INSTANTIATE_TEST_SUITE_P(RSAHelperDifferentKeySize,
                         RSAHelperTest2,
                         ::testing::Values(std::make_pair("./1024.cert", "./1024.key"),
                                           std::make_pair("./2048.cert", "./2048.key"),
                                           std::make_pair("./4096.cert", "./4096.key")));

/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <base/utils/rocksDBWrapper.hpp>
#include <base/utils/rsaHelper.hpp>

#include "keyStore.hpp"

/**
 * @brief KeyStoreComponentTest class.
 *
 */
class KeyStoreComponentTest : public ::testing::Test
{
protected:
    KeyStoreComponentTest() = default;
    ~KeyStoreComponentTest() override = default;
    void SetUp() override;
};

void KeyStoreComponentTest::SetUp()
{
    logging::testInit();
}

constexpr auto DATABASE_PATH {"queue/keystore"};
constexpr auto KS_VERSION {"2"};
constexpr auto KS_VERSION_FIELD {"version"};

constexpr const char* RSA_CERTIFICATE = R"(
-----BEGIN CERTIFICATE-----
MIICzjCCAbYCAQEwDQYJKoZIhvcNAQELBQAwLTELMAkGA1UEBhMCVVMxDjAMBgNV
BAoMBVdhenVoMQ4wDAYDVQQDDAVXYXp1aDAeFw0yNDA3MTIwMzQ1MjZaFw0yNTA3
MTIwMzQ1MjZaMC0xCzAJBgNVBAYTAlVTMQ4wDAYDVQQKDAVXYXp1aDEOMAwGA1UE
AwwFV2F6dWgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAF7MiRby8
tznjvg8O28wvK4Y0bC3rnmP8noj0xf9ddQidBj/O8rsc4o1PvZNlWcdyQieUUXjw
d/n0MHIAAeq2doDOC0S39Fll2iSWS36fILx3fZI8vBanlQIqstJBH+JfGu5dNugp
K+kj1+sXP4ySGwXQE0qmJLLd9pI8pmZb1FNu2GPe+/qSEqxkq77o53KnzuDboBj4
qiDqR4csxKMga6QoOa7bBZBwdst8CUxwGAPMioPMcNmmv3LhbFbPAML3UEvrUE4U
fWPs6ReIZyvGgaUVwqwd0kWav/3UkTFMlX7boIUt4uL8EISXwNHnaCkZGT/G5XMc
UC/F4Juhjl4ZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABuhuYEug4A/wAs0f4vY
UGBHySeV8Hh6CyTS80DYctxAzOnK2+eY5CTPgDGocot7UKZI+Gaqim1R3nffQovl
8Z41wghbQQ7YNLljBuK5YqrhxMu5g/F8qyNC45y/dd0fKEAeN+23BDiJzUpCh+VZ
gFTl+6IXDam4AtaRECYw0z6zn81x9+YNCLpbdzjj4k0XB3WF/hlAbDOsbbOl2Af8
toyHagx7dgachxiRBDRfarM4DygZ4mKblgfIsb538YLSiVZ4ZwO0hdiEHI+Wsfq4
RLPjnbFuS9IPeb4VQVuxvqx2cSw1rovbqOshozghTfx2on7nnekNJ1QRry+occMK
FFo=
-----END CERTIFICATE-----
)";

constexpr const char* RSA_KEY = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAF7MiRby8tznj
vg8O28wvK4Y0bC3rnmP8noj0xf9ddQidBj/O8rsc4o1PvZNlWcdyQieUUXjwd/n0
MHIAAeq2doDOC0S39Fll2iSWS36fILx3fZI8vBanlQIqstJBH+JfGu5dNugpK+kj
1+sXP4ySGwXQE0qmJLLd9pI8pmZb1FNu2GPe+/qSEqxkq77o53KnzuDboBj4qiDq
R4csxKMga6QoOa7bBZBwdst8CUxwGAPMioPMcNmmv3LhbFbPAML3UEvrUE4UfWPs
6ReIZyvGgaUVwqwd0kWav/3UkTFMlX7boIUt4uL8EISXwNHnaCkZGT/G5XMcUC/F
4Juhjl4ZAgMBAAECggEAB4JlrFdRk4cOKksJx6jsCIQJEQ+Rk/5zJjMEY51B6GNk
3M6bu/ldOznYEF/23SVvWJYhefjdY3ktOlCShFGO3Wcwjd1+6DoTLJokiAOXhZ0A
ASPVja5ErHR0yzqGYalfbhxdaSN2W/WtfYs5U4VWd3e6+HFon6obm/XBrcFLixdm
fLrO8Arb+HnunsihQGw1DSkGrTCzJgHqHPqcehKiIMfgNRrg2YNqF3z2WfucEi1s
J6GNjVVtJ9C96ZJ1zTyROPriQTqT3QLwUp+IbWF+sY63oGRRGtOvtl3kOh7TN44o
O7DTfIuvirEk239XFVU2ErC5sV6ujnF1NlOcyiTWAQKBgQDgNI3zzIHno3rsdLGn
WvHPJ1hX9awJnwJOI1jyIqvC3QfGeiijSj0vIY5Ga8YUAoglIt65LC7YYnR2SeR/
9imKHHOR4wq9ugcWe1mjTT9nnGfuJfDMkPSEnVyxvwU/dmYAlp0TVX7Ys4saO7d0
x893Ahky9gWvsGu+nJzvgdWOeQKBgQDbVVcPqZRAkBOLG2sAEU+e9/ZAVVQmqUl8
J8iqjeIZRvyl01Qyfvhh0U0OqVjMVW52cFhWoMJ0pwaq0wv/pT5+2HQVv9hXCgtz
2332cB8qYR3LApxdiZb0i1ENVP3sANCWqm2k3kTbFRe/B3udzjsHO7ESzT1MM7wb
pkjBuzzkoQKBgAXUV/yGzLnhHkkXn6biTnc8Zqei055MbBrsAFwLWrvuU01tz7Cv
NXgMP07FbpkGl9OfXHskEvO9W5nXwgExvVLB+p9Ib/cO5zBGdMYyM/vVrT4b7m7j
NfhcvxRACzrjMTPCtsLR7kJkKLG96781ksddXppcmzk+NQ73s3zmu07BAoGBALJl
eleh7ZSJ22uE1IYMjn9VXfS7sqNzg/K5BS08FA/NPke+WLhtr6cYLx3ivfgM8Lji
7ecgAKoTBIhC+npntCpF8j2SeetpnyEQASdF0QOOVEZADGDEPYUQH8/BNnsTupUh
b+buZoDvag4VjwUurbJXadJKHzZwyeqPWJRCr+ehAoGADT5lzb2iu8GXKVmVleT8
BOlDVO7hSpr5iIAzLlUQbTTnyuHNgYMFyXXyUUflVKWe0he5WPxEeKIa9AyV6aWN
ADGD78yxRpOd4XJ4dq5TmKhs5sniGThg7UawNOXjjZ5qP2LPm+x5TNZA0URWTUTz
mRUOzQ0+gdZF139yMrSAoAo=
-----END PRIVATE KEY-----
)";
std::string getKeystoreVersion()
{
    auto keystoreDB = utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false);
    std::string value;
    keystoreDB.get(KS_VERSION_FIELD, value, "default");
    return value;
}

void writeRSACertAndPk(const std::filesystem::path& certPath, const std::filesystem::path& pkPath)
{
    std::ofstream cert(certPath.c_str());
    cert << RSA_CERTIFICATE;
    cert.close();

    std::ofstream pk(pkPath);
    pk << RSA_KEY;
    pk.close();
}

TEST_F(KeyStoreComponentTest, TestPutGet)
{
    std::filesystem::remove_all(DATABASE_PATH);

    // Check that the keystore version is empty when the database is empty
    ASSERT_EQ(getKeystoreVersion(), "");

    // Put a value in the keystore and check that the version is updated
    Keystore::put("default", "key1", "value1");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);
    Keystore::put("default", "key2", "value2");

    // Get the value from the keystore and check that it is the same as the one put
    std::string out;
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "value1");
    Keystore::get("default", "key2", out);
    ASSERT_EQ(out, "value2");
}

TEST_F(KeyStoreComponentTest, TestUpgrade)
{
    std::filesystem::remove_all(DATABASE_PATH);

    // Create a new RSA key pair using the path specified in the Keystore class.
    std::filesystem::remove("etc/sslmanager.key");
    std::filesystem::remove("etc/sslmanager.cert");
    std::filesystem::create_directory("etc");
    writeRSACertAndPk("etc/sslmanager.cert", "etc/sslmanager.key");

    // Encrypt the value and store it in the keystore. to simulate the previous algorithm
    std::string out;
    RSAHelper().rsaEncrypt("etc/sslmanager.cert", "value1", out, true);
    utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false).put("key1", out, "default");
    RSAHelper().rsaEncrypt("etc/sslmanager.cert", "value2", out, true);
    utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false).put("key2", out, "default");

    // Get the value and decrypt it with the new algorithm
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "value1");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);

    Keystore::get("default", "key2", out);
    ASSERT_EQ(out, "value2");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);
}

TEST_F(KeyStoreComponentTest, TestUpgradeFail)
{
    std::filesystem::remove_all(DATABASE_PATH);
    utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false).put("key1", "rawrawraw", "default");

    // Check if in the case of an invalid value the keystore is upgraded and the values are deleted
    std::string out;
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);

    // Check if we can put a new value in the keystore after the failed upgrade.
    Keystore::put("default", "key1", "value1");
    Keystore::put("default", "key2", "value2");

    // Get the value from the keystore and check that it is the same as the one put
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "value1");
    Keystore::get("default", "key2", out);
    ASSERT_EQ(out, "value2");
}

TEST_F(KeyStoreComponentTest, TestUpgradeFailWithInvalidCerts)
{
    std::filesystem::remove_all(DATABASE_PATH);
    // Create a new RSA key pair using the path specified in the Keystore class.
    std::filesystem::remove("etc/sslmanager.key");
    std::filesystem::remove("etc/sslmanager.cert");
    std::filesystem::create_directory("etc");
    writeRSACertAndPk("etc/sslmanager.cert", "etc/sslmanager.key");

    // Encrypt the value and store it in the keystore. to simulate the previous algorithm
    std::string out;
    RSAHelper().rsaEncrypt("etc/sslmanager.cert", "value1", out, true);
    utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false).put("key1", out, "default");
    RSAHelper().rsaEncrypt("etc/sslmanager.cert", "value2", out, true);
    utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false).put("key2", out, "default");

    // Write invalid certificates
    std::ofstream cert("etc/sslmanager.cert");
    cert << "invalid";
    cert.close();

    std::ofstream pk("etc/sslmanager.key");
    pk << "invalid";
    pk.close();

    // Check if in the case of an invalid value the keystore is upgraded and the values are deleted
    out = "";
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);

    // Check if we can put a new value in the keystore after the failed upgrade.
    Keystore::put("default", "key1", "value1");
    Keystore::put("default", "key2", "value2");

    // Get the value from the keystore and check that it is the same as the one Put
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "value1");
    Keystore::get("default", "key2", out);
    ASSERT_EQ(out, "value2");
}

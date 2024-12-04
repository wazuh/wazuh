#include <filesystem>
#include <gtest/gtest.h>
#include <memory>

#include <base/logging.hpp>
#include <base/utils/evpHelper.hpp>
#include <base/utils/keyValueFile.hpp>

auto constexpr TEST_KEY_VALUE_FILE {"key_value_test.keys"};
auto constexpr TEST_KEY_VALUE_FILE_SEPARATOR {"key_value_test_separator.keys"};

class keyValueFileTest : public ::testing::Test
{

protected:
    std::unique_ptr<base::utils::KeyValueFile> keyValue;
    void SetUp() override
    {
        logging::testInit();
        keyValue = std::make_unique<base::utils::KeyValueFile>(TEST_KEY_VALUE_FILE);
    }

    void TearDown() override
    {
        keyValue.reset();
        std::filesystem::remove(TEST_KEY_VALUE_FILE);
        std::filesystem::remove(TEST_KEY_VALUE_FILE_SEPARATOR);
    }
};

TEST_F(keyValueFileTest, CreationAndPermissions)
{
    auto status = std::filesystem::status(TEST_KEY_VALUE_FILE);
    auto perms = status.permissions();

    ASSERT_TRUE(std::filesystem::exists(TEST_KEY_VALUE_FILE));
    ASSERT_TRUE(std::filesystem::is_regular_file(TEST_KEY_VALUE_FILE));
    ASSERT_TRUE((perms & std::filesystem::perms::owner_read) != std::filesystem::perms::none);
    ASSERT_TRUE((perms & std::filesystem::perms::owner_write) != std::filesystem::perms::none);
    ASSERT_TRUE((perms & std::filesystem::perms::group_read) != std::filesystem::perms::none);

    ASSERT_FALSE((perms & std::filesystem::perms::owner_exec) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::group_write) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::group_exec) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::others_read) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::others_write) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::others_exec) != std::filesystem::perms::none);
}

TEST_F(keyValueFileTest, PutAndGet)
{
    std::string value;
    ASSERT_FALSE(keyValue->get("key", value));

    keyValue->put("key", "value");
    ASSERT_TRUE(keyValue->get("key", value));
    ASSERT_EQ(value, "value");
}

TEST_F(keyValueFileTest, PutAndGetMultiple)
{
    std::string value;
    ASSERT_FALSE(keyValue->get("key1", value));
    ASSERT_FALSE(keyValue->get("key2", value));

    keyValue->put("key1", "value1");
    keyValue->put("key2", "value2");

    ASSERT_TRUE(keyValue->get("key1", value));
    ASSERT_EQ(value, "value1");

    ASSERT_TRUE(keyValue->get("key2", value));
    ASSERT_EQ(value, "value2");
}

TEST_F(keyValueFileTest, PutAndGetOverwrite)
{
    std::string value;
    ASSERT_FALSE(keyValue->get("key", value));

    keyValue->put("key", "value1");
    ASSERT_TRUE(keyValue->get("key", value));
    ASSERT_EQ(value, "value1");

    keyValue->put("key", "value2");
    ASSERT_TRUE(keyValue->get("key", value));
    ASSERT_EQ(value, "value2");
}

TEST_F(keyValueFileTest, PutAndGetEmpty)
{
    EXPECT_ANY_THROW(keyValue->put("", "value"));
    EXPECT_ANY_THROW(keyValue->put("key", ""));
    EXPECT_ANY_THROW(keyValue->put("", ""));
}

TEST_F(keyValueFileTest, PutAndGetWithSeparator)
{
    EXPECT_ANY_THROW(keyValue->put(std::string("key") + base::utils::KEY_VALUE_SEPARATOR, "value"));
    EXPECT_NO_THROW(keyValue->put("key", std::string("value") + base::utils::KEY_VALUE_SEPARATOR));
    EXPECT_ANY_THROW(keyValue->put(std::string("key") + base::utils::KEY_VALUE_SEPARATOR,
                                   std::string("value") + base::utils::KEY_VALUE_SEPARATOR));
}

TEST_F(keyValueFileTest, PutAndGetNonDefaultSeparator)
{
    base::utils::KeyValueFile keyValueSeparator(TEST_KEY_VALUE_FILE_SEPARATOR, '=');

    std::string value;
    ASSERT_FALSE(keyValueSeparator.get("key", value));

    keyValueSeparator.put("key", "value");
    ASSERT_TRUE(keyValueSeparator.get("key", value));
    ASSERT_EQ(value, "value");
}

TEST_F(keyValueFileTest, PutAndGetRandomEncryptedValues)
{
    std::vector<char> encryptedValue;
    std::string valueToEncrypt = "test_value_to_be_encrypted_by_aes256";

    base::utils::EVPHelper().encryptAES256(valueToEncrypt, encryptedValue);
    keyValue->put("key", encryptedValue);

    std::string encryptedValueStr;
    std::string readValue;
    ASSERT_TRUE(keyValue->get("key", encryptedValueStr));
    std::vector<char> encryptedValueVec(encryptedValueStr.begin(), encryptedValueStr.end());
    base::utils::EVPHelper().decryptAES256(encryptedValueVec, readValue);

    ASSERT_EQ(valueToEncrypt, readValue);
}

TEST_F(keyValueFileTest, PutAndGetBinaryValue)
{
    std::vector<char> binaryValue = {'\x00', '\xFA', '#',    '1',    'o',    '\xDA', '_',    'V',  '\t',   '\xCA',
                                     '\xAE', '\x9A', '\x3E', ']',    '\x21', 'e',    '\n',   '`',  'w',    '\xAA',
                                     '3',    'd',    '\x55', '\x2F', '\xBB', '}',    '\xA0', '8',  '*',    '#',
                                     '\x10', '1',    '\'',   '\x2D', '\xDD', '\xAF', '\xFA', '	', '|',    '\x1A',
                                     '\xF9', 'i',    'H',    '\x15', '\\',   'P',    '!',    '"',  '\x99', '$',
                                     '%',    '&',    'm',    '/',    '(',    ')',    'z',    '=',  ':',    '?'};
    keyValue->put("key", binaryValue);

    std::vector<char> readValueVec;
    ASSERT_TRUE(keyValue->get("key", readValueVec));

    ASSERT_EQ(binaryValue, readValueVec);
}

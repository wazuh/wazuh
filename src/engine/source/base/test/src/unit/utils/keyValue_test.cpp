#include <filesystem>
#include <gtest/gtest.h>
#include <memory>

#include <base/logging.hpp>
#include <base/utils/evpHelper.hpp>
#include <base/utils/keyValue.hpp>

class keyValueTest : public ::testing::Test
{

protected:
    std::unique_ptr<base::utils::KeyValue> keyValue;
    void SetUp() override
    {
        logging::testInit();
        keyValue = std::make_unique<base::utils::KeyValue>();
    }

    void TearDown() override { keyValue.reset(); }
};

TEST_F(keyValueTest, PutAndGet)
{
    std::string value;
    ASSERT_FALSE(keyValue->get("key", value));

    keyValue->put("key", "value");
    ASSERT_TRUE(keyValue->get("key", value));
    ASSERT_EQ(value, "value");
}

TEST_F(keyValueTest, PutAndGetMultiple)
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

TEST_F(keyValueTest, PutAndGetOverwrite)
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

TEST_F(keyValueTest, PutAndGetEmpty)
{
    EXPECT_ANY_THROW(keyValue->put("", "value"));
    EXPECT_ANY_THROW(keyValue->put("key", ""));
    EXPECT_ANY_THROW(keyValue->put("", ""));
}

TEST_F(keyValueTest, PutAndGetWithSeparator)
{
    EXPECT_ANY_THROW(keyValue->put(std::string("key") + base::utils::KEY_VALUE_SEPARATOR, "value"));
    EXPECT_ANY_THROW(keyValue->put("key", std::string("value") + base::utils::KEY_VALUE_SEPARATOR));
    EXPECT_ANY_THROW(keyValue->put(std::string("key") + base::utils::KEY_VALUE_SEPARATOR,
                                   std::string("value") + base::utils::KEY_VALUE_SEPARATOR));
}

TEST_F(keyValueTest, PutAndGetNonDefaultSeparator)
{
    base::utils::KeyValue keyValueSeparator("", '=');

    std::string value;
    ASSERT_FALSE(keyValueSeparator.get("key", value));

    keyValueSeparator.put("key", "value");
    ASSERT_TRUE(keyValueSeparator.get("key", value));
    ASSERT_EQ(value, "value");
}

TEST_F(keyValueTest, PutAndGetBinaryValue)
{
    std::string binaryValue = {'\x00', '\xFA', '#',    '1',    'o',    '\xDA', '_',    'V',    '\t',   '\xCA',
                               '\xAE', '\x9A', '\x3E', ']',    '\x21', 'e',    '\xEA', '-',    'w',    '\xAA',
                               '3',    'd',    '\x55', '\x2F', '\xBB', '}',    '\xA0', '8',    '*',    '#',
                               '\x10', '1',    '\'',   '\x2D', '\xDD', '\xAF', '\xFA', '	', '|',    '\x1A',
                               '\xF9', 'i',    'H',    '\x15', '\\',   'P',    '!',    '"',    '\x99', '$',
                               '%',    '&',    'm',    '/',    '(',    ')',    'z',    '=',    '\x01', '?'};
    keyValue->put("key", binaryValue);

    std::string readValueVec;
    ASSERT_TRUE(keyValue->get("key", readValueVec));

    ASSERT_EQ(binaryValue, readValueVec);
}

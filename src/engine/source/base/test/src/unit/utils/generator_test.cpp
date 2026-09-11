#include <gtest/gtest.h>

#include <cctype>
#include <set>

#include <base/utils/generator.hpp>

using namespace base::utils::generators;

TEST(GeneratorTest, GenerateUUIDv4Format)
{
    const auto uuid = generateUUIDv4();

    ASSERT_EQ(uuid.size(), UUID_V4_LENGTH);
    EXPECT_EQ(uuid[8], '-');
    EXPECT_EQ(uuid[13], '-');
    EXPECT_EQ(uuid[18], '-');
    EXPECT_EQ(uuid[23], '-');
    EXPECT_EQ(uuid[14], '4');
    EXPECT_TRUE(uuid[19] == '8' || uuid[19] == '9' || uuid[19] == 'a' || uuid[19] == 'b');

    for (size_t i = 0; i < uuid.size(); ++i)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            continue;
        }
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(uuid[i]))) << "at index " << i;
    }
}

TEST(GeneratorTest, GenerateUUIDv4IsUnique)
{
    std::set<std::string> uuids;
    for (size_t i = 0; i < 1000; ++i)
    {
        uuids.insert(generateUUIDv4());
    }

    EXPECT_EQ(uuids.size(), 1000U);
}

TEST(GeneratorTest, IsValidResourceIdRejectsEmpty)
{
    EXPECT_FALSE(isValidResourceId(""));
}

TEST(GeneratorTest, IsValidResourceIdAcceptsAnyUUIDVersion)
{
    // Identifiers are opaque to the engine, the version and variant are never interpreted
    EXPECT_TRUE(isValidResourceId(generateUUIDv4()));
    EXPECT_TRUE(isValidResourceId("6093809a-6285-5cf8-9284-63bd68f796e9")); // v5
    EXPECT_TRUE(isValidResourceId("0199a9f4-1b1e-7c3b-8f2a-2f9a1c0d4e5f")); // v7
    EXPECT_TRUE(isValidResourceId("00000000-0000-0000-0000-000000000000")); // nil
    EXPECT_TRUE(isValidResourceId("6093809A-6285-5CF8-9284-63BD68F796E9")); // uppercase
}

TEST(GeneratorTest, IsValidResourceIdAcceptsNonUUIDIdentifiers)
{
    EXPECT_TRUE(isValidResourceId("not-a-uuid"));
    EXPECT_TRUE(isValidResourceId("decoder/windows/0"));
    EXPECT_TRUE(isValidResourceId("0"));
    EXPECT_TRUE(isValidResourceId("with space"));
    EXPECT_TRUE(isValidResourceId("MixedCase-Id_1.2"));
    EXPECT_TRUE(isValidResourceId("identificador-ñ-日本"));                   // UTF-8 is not a control character
    EXPECT_TRUE(isValidResourceId(std::string(MAX_RESOURCE_ID_LENGTH, 'a'))); // exactly at the limit
}

TEST(GeneratorTest, IsValidResourceIdRejectsControlCharacters)
{
    EXPECT_FALSE(isValidResourceId("bad\nid"));
    EXPECT_FALSE(isValidResourceId("bad\tid"));
    EXPECT_FALSE(isValidResourceId("bad\rid"));
    EXPECT_FALSE(isValidResourceId(std::string("bad\0id", 6)));
    EXPECT_FALSE(isValidResourceId("bad\x1bid")); // ESC
    EXPECT_FALSE(isValidResourceId("bad\x7fid")); // DEL
    EXPECT_FALSE(isValidResourceId("\n"));
}

TEST(GeneratorTest, IsValidResourceIdRejectsOversizedIdentifiers)
{
    EXPECT_FALSE(isValidResourceId(std::string(MAX_RESOURCE_ID_LENGTH + 1, 'a')));
    EXPECT_FALSE(isValidResourceId(std::string(4096, 'a')));
}

TEST(GeneratorTest, RandomHexStringLength)
{
    EXPECT_TRUE(randomHexString(0).empty());

    const auto hex = randomHexString(16);
    ASSERT_EQ(hex.size(), 16U);
    for (const auto c : hex)
    {
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
    }
}

#include "string_helper_test.h"
#include "string_helper.h"

void StringHelperTest::SetUp() {};

void StringHelperTest::TearDown() {};

TEST_F(StringHelperTest, CheckReplacement) 
{
    std::string string_base { "hello_world" };
    const auto ret_val { StringHelper::replace_string(string_base, "hello_", "bye_") };
    EXPECT_EQ(string_base, "bye_world");
    EXPECT_TRUE(ret_val);
}

TEST_F(StringHelperTest, CheckNotReplacement) 
{
    std::string string_base {"hello_world" };
    const auto ret_val { StringHelper::replace_string(string_base, "nothing_", "bye_") };
    EXPECT_EQ(string_base, "hello_world");
    EXPECT_FALSE(ret_val);
}

TEST_F(StringHelperTest, SplitEmptyString) 
{
    auto split_text_vector { StringHelper::split("", '.') };
    EXPECT_EQ(0ull, split_text_vector.size());
}

TEST_F(StringHelperTest, SplitDelimiterNoCoincidence) 
{
    const auto split_text_vector { StringHelper::split("hello_world", '.') };
    EXPECT_EQ(1ull, split_text_vector.size());
}

TEST_F(StringHelperTest, SplitDelimiterCoincidence) 
{
    const auto split_text_vector { StringHelper::split("hello.world", '.') };
    EXPECT_EQ(2ull, split_text_vector.size());
    EXPECT_EQ(split_text_vector[0], "hello");
    EXPECT_EQ(split_text_vector[1], "world");
}


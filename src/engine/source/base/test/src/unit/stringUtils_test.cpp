#include <gtest/gtest.h>

#include <vector>

#include <base/utils/stringUtils.hpp>

TEST(split, null_del)
{
    std::string test = "test";
    std::vector<std::string> expected = {"test"};
    std::vector<std::string> result = base::utils::string::split(test, '\0');
    ASSERT_EQ(result, expected);
}

TEST(split, not_delimiter)
{
    std::string test = "test";
    std::vector<std::string> expected = {"test"};
    std::vector<std::string> result = base::utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, middle_delimiter)
{
    std::string test = "value1/value2";
    std::vector<std::string> expected = {"value1", "value2"};
    std::vector<std::string> result = base::utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, first_delimiter)
{
    std::string test = "/value1/value2";
    std::vector<std::string> expected = {"value1", "value2"};
    std::vector<std::string> result = base::utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, final_delimiter)
{
    std::string test = "value1/value2/";
    std::vector<std::string> expected = {"value1", "value2"};
    std::vector<std::string> result = base::utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

// Double empty section at middle and end
TEST(split, doble_delimiter)
{
    std::string test = "//value1//value2//";
    std::vector<std::string> expected = {"", "value1", "", "value2", ""};
    std::vector<std::string> result = base::utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, ok_delimiter)
{
    std::string test = "value1/value2/value3";
    std::vector<std::string> expected = {"value1", "value2", "value3"};
    std::vector<std::string> result = base::utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(splitMulti, ThreeDelimiters)
{
    std::string input = "this is-a test to split by - and ,,where-are included in the result";
    std::vector<std::string> expected = {"this",
                                         "is",
                                         "-",
                                         "a",
                                         "test",
                                         "to",
                                         "split",
                                         "by",
                                         "-",
                                         "and",
                                         "where",
                                         "-",
                                         "are",
                                         "included",
                                         "in",
                                         "the",
                                         "result"};
    std::vector<std::string> result = base::utils::string::splitMulti(input,
                                                                      base::utils::string::Delimeter('-', true),
                                                                      base::utils::string::Delimeter(',', false),
                                                                      base::utils::string::Delimeter(' ', false));
    ASSERT_EQ(result, expected);
}

// Difference of behavior between split and splitMulti with empty strings
TEST(splitMulti, SingleDelimiterAndEmptyAtEnd)
{
    std::string input = "this is/a test/to split by / where/are included in/the// result//";
    std::vector<std::string> expected = {
        "this is", "a test", "to split by ", " where", "are included in", "the", " result"};
    std::vector<std::string> result =
        base::utils::string::splitMulti(input, base::utils::string::Delimeter('/', false));
    ASSERT_EQ(result, expected);
}

TEST(startsWith, Success)
{
    std::string input = "this is a test";
    std::string prefix = "this";
    ASSERT_TRUE(base::utils::string::startsWith(input, prefix));
}

TEST(startsWith, Failure)
{
    std::string input = "this is a test";
    std::string prefix = "that";
    ASSERT_FALSE(base::utils::string::startsWith(input, prefix));

    prefix = "his is";
    ASSERT_FALSE(base::utils::string::startsWith(input, prefix));
}

TEST(join, defaut_separator)
{
    const std::string expected = "test";
    const std::vector<std::string> test = {"test"};
    const std::string result = base::utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(join, not_defaut_separator_starting_with_it)
{
    const std::string expected = ",test";
    const std::string separator = ",";
    const std::vector<std::string> test = {"test"};
    std::string result = base::utils::string::join(test, separator, true);
    ASSERT_EQ(result, expected);
}

TEST(join, not_defaut_separator_several_strings_starting_with_it)
{
    const std::string expected = ",test1,test2,test3,test4";
    const std::string separator = ",";
    const std::vector<std::string> test = {"test1", "test2", "test3", "test4"};
    std::string result = base::utils::string::join(test, separator, true);
    ASSERT_EQ(result, expected);
}

TEST(join, not_defaut_separator_several_strings)
{
    const std::string expected = "test1,test2,test3,test4";
    const std::string separator = ",";
    const std::vector<std::string> test = {"test1", "test2", "test3", "test4"};
    std::string result = base::utils::string::join(test, separator, false);
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator_several_strings)
{
    const std::string expected = "test1test2test3test4";
    const std::vector<std::string> test = {"test1", "test2", "test3", "test4"};
    const std::string result = base::utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator_none_input)
{
    const std::string expected = "";
    const std::vector<std::string> test = {};
    const std::string result = base::utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator_empty_strings_array_as_input)
{
    const std::string expected = "";
    const std::vector<std::string> test = {"", "", ""};
    const std::string result = base::utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(splitEscaped, SuccessDefaultValues)
{
    std::string input = R"(+helper_function/param\/et\/er/param2/param3)";
    std::vector<std::string> expected = {"+helper_function", R"(param/et/er)", "param2", "param3"};
    std::vector<std::string> result = base::utils::string::splitEscaped(input);
    ASSERT_EQ(result, expected);
}

TEST(splitEscaped, SuccessEmptyFields)
{
    std::string input = R"(+123456/ABC\/DE\/12/test/!//)";
    std::vector<std::string> expected = {"+123456", R"(ABC/DE/12)", "test", "!", "", ""};
    std::vector<std::string> result = base::utils::string::splitEscaped(input);
    ASSERT_EQ(result, expected);

    std::string input2 = R"(+123//456/ABC/!)";
    std::vector<std::string> expected2 = {"+123", "", "456", "ABC", "!"};
    std::vector<std::string> result2 = base::utils::string::splitEscaped(input2);
    ASSERT_EQ(result2, expected2);
}

// Escaping a non splitting char: this doesn't fail because I need to be able to escape different chars like in regex
TEST(splitEscaped, EndingScaped)
{
    std::string input = R"(ABCD\\)";
    std::vector<std::string> expected = {R"(ABCD\)"};
    std::vector<std::string> result = base::utils::string::splitEscaped(input);
    ASSERT_EQ(result, expected);
}

// nothing to replace
TEST(splitEscaped, SuccessNothingChanged)
{
    std::string allCharsWithoutEscape {
        R"(!#$%&()*+,-.0123456789:;<=>?@ ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~)"};
    std::vector<std::string> expected {allCharsWithoutEscape};

    std::vector<std::string> result = base::utils::string::splitEscaped(allCharsWithoutEscape);
    ASSERT_EQ(result, expected);
}

// Replacing 3 times without splitting
TEST(splitEscaped, SuccessNoSplit)
{
    std::string input = R"(\/ABCDEFGHIJKLMN\/OPQRSTUVWXYZ\/)";
    std::vector<std::string> expected = {R"(/ABCDEFGHIJKLMN/OPQRSTUVWXYZ/)"};
    std::vector<std::string> result = base::utils::string::splitEscaped(input);
    ASSERT_EQ(result, expected);
}

// Replacing and splitting with different separator
TEST(splitEscaped, SuccessSplitDifferentEscape)
{
    std::string input = R"(#!ABC!DEFGH!IJKLM!N#!OP!QRST!UVWX!YZ#!)";
    std::vector<std::string> expected = {"!ABC", "DEFGH", "IJKLM", "N!OP", "QRST", "UVWX", "YZ!"};
    std::vector<std::string> result = base::utils::string::splitEscaped(input, '!', '#');
    ASSERT_EQ(result, expected);
}

// Different escaped characters: this doesn't fail because I need to be able to escape different chars like in regex
TEST(splitEscaped, AnotherEscapedCharacters)
{
    std::string input = R"(#!ABC!DEFGH!IJKLM!N#?OP!QRST!UVWX!YZ#!)";
    std::vector<std::string> expected = {"!ABC", "DEFGH", "IJKLM", "N#?OP", "QRST", "UVWX", "YZ!"};
    std::vector<std::string> result = base::utils::string::splitEscaped(input, '!', '#');
    ASSERT_EQ(result, expected);
}

TEST(splitEscaped, EcapeEscapedChar)
{
    std::string input = R"(#!ABC!DE##FGH)";
    std::vector<std::string> expected = {"!ABC", "DE#FGH"};
    std::vector<std::string> result = base::utils::string::splitEscaped(input, '!', '#');
    ASSERT_EQ(result, expected);
}

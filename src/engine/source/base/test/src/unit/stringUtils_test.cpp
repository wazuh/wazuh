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

TEST(endsWith, Success)
{
    std::string input = "this is a test";
    std::string suffix = "test";
    ASSERT_TRUE(base::utils::string::endsWith(input, suffix));

    suffix = "this is a test";
    ASSERT_TRUE(base::utils::string::endsWith(input, suffix));
}

TEST(endsWith, Failure)
{
    std::string input = "this is a test";
    std::string suffix = "is a test1";
    ASSERT_FALSE(base::utils::string::endsWith(input, suffix));

    suffix = "test1";
    ASSERT_FALSE(base::utils::string::endsWith(input, suffix));

    suffix = "this is a test1";
    ASSERT_FALSE(base::utils::string::endsWith(input, suffix));
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

TEST(StringUtilsTest, CheckReplacementReplace)
{
    std::string string_base = "The quick brown fox jumps over the lazy fox";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "fox", "dog"));
    EXPECT_EQ(string_base, "The quick brown dog jumps over the lazy dog");
}

TEST(StringUtilsTest, CheckReplacementReplaceIsInSearch)
{
    std::string string_base = "aaaa aaaaa a";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "aa", "a"));
    EXPECT_EQ(string_base, "a a a");
}

TEST(StringUtilsTest, BasicOverlapReplacement)
{
    std::string string_base = "abababab";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "aba", "a"));
    EXPECT_EQ(string_base, "ab");
}

TEST(StringUtilsTest, OverlapWithSmallerReplacement)
{
    std::string string_base = "aaaaa";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "aa", "a"));
    EXPECT_EQ(string_base, "a");
}

TEST(StringUtilsTest, ReplaceEmptySearchString)
{
    std::string string_base = "this should not change";
    EXPECT_FALSE(base::utils::string::replaceAll(string_base, "", "new"));
    EXPECT_EQ(string_base, "this should not change");
}

TEST(StringUtilsTest, SearchEqualsReplace)
{
    std::string string_base = "no change expected";
    EXPECT_FALSE(base::utils::string::replaceAll(string_base, "change", "change"));
    EXPECT_EQ(string_base, "no change expected");
}

TEST(StringUtilsTest, ReplaceWithLongerString)
{
    std::string string_base = "ab cd ef";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, " ", "_verylongseparator_"));
    EXPECT_EQ(string_base, "ab_verylongseparator_cd_verylongseparator_ef");
}

TEST(StringUtilsTest, NoOccurrence)
{
    std::string string_base = "there is no match here";
    EXPECT_FALSE(base::utils::string::replaceAll(string_base, "xyz", "replacement"));
    EXPECT_EQ(string_base, "there is no match here");
}

TEST(StringUtilsTest, PartialMatches)
{
    std::string string_base = "abacada";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "aba", "x"));
    EXPECT_EQ(string_base, "xcada");
}

TEST(StringUtilsTest, ExitConditionRecursion)
{
    std::string string_base = "a";
    EXPECT_FALSE(base::utils::string::replaceAll(string_base, "a", "aa"));
}

TEST(StringUtilsTest, ContinuousReplacements)
{
    std::string string_base = "abababababab";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "ab", "cd"));
    EXPECT_EQ(string_base, "cdcdcdcdcdcd");
}

TEST(StringUtilsTest, ReplaceWithEmptyString)
{
    std::string string_base = "remove this remove this";
    EXPECT_TRUE(base::utils::string::replaceAll(string_base, "remove", ""));
    EXPECT_EQ(string_base, " this  this");
}

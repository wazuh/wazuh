#include "sca_utils.hpp"
#include <gtest/gtest.h>

#include "logging_helper.hpp"

using namespace sca;

class ParseRuleTypeTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Set up the logging callback to avoid "Log callback not set" errors
        LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {
            // Mock logging callback that does nothing
        });

    }
};

// NOLINTBEGIN(bugprone-unchecked-optional-access, modernize-raw-string-literal)
TEST_F(ParseRuleTypeTest, ValidTypes)
{
    auto result = ParseRuleType("f:/path");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->first, WM_SCA_TYPE_FILE);
    EXPECT_EQ(result->second, "/path");

    result = ParseRuleType("r:HKEY_LOCAL_MACHINE\\...");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->first, WM_SCA_TYPE_REGISTRY);

    result = ParseRuleType("p:proc");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->first, WM_SCA_TYPE_PROCESS);

    result = ParseRuleType("d:/dir");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->first, WM_SCA_TYPE_DIR);

    result = ParseRuleType("c:echo");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->first, WM_SCA_TYPE_COMMAND);
}

TEST_F(ParseRuleTypeTest, NegatedKey)
{
    const auto result = ParseRuleType("!f:/negated");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->first, WM_SCA_TYPE_FILE);
    EXPECT_EQ(result->second, "/negated");
}

TEST_F(ParseRuleTypeTest, InvalidInputs)
{
    EXPECT_FALSE(ParseRuleType("x:invalid"));
    EXPECT_FALSE(ParseRuleType(":missing"));
    EXPECT_FALSE(ParseRuleType("missingcolon"));
    EXPECT_FALSE(ParseRuleType(""));
}

TEST(GetPatternTest, ValidPattern)
{
    auto result = GetPattern("rule -> pattern");
    ASSERT_TRUE(result);
    EXPECT_EQ(*result, "pattern");

    result = GetPattern("x -> y -> z");
    ASSERT_TRUE(result);
    EXPECT_EQ(*result, "y -> z");

    result = GetPattern(" -> only");
    ASSERT_TRUE(result);
    EXPECT_EQ(*result, "only");
}

TEST(GetPatternTest, InvalidPattern)
{
    EXPECT_FALSE(GetPattern(""));
    EXPECT_FALSE(GetPattern("no arrow here"));
}

TEST(PatternMatchesTest, InvalidCompareStringReturnsNullopt)
{
    const auto patternMatch = PatternMatches("match", "n:123 c0mp4r3 >= 123");
    ASSERT_FALSE(patternMatch.has_value());
}

TEST(PatternMatchesTest, InvalidComparisonOperatorReturnsNullopt)
{
    const auto patternMatch = PatternMatches("123", "n:123 compare !! 123");
    ASSERT_FALSE(patternMatch.has_value());
}

TEST(PatternMatchesTest, InvalidOperandForComparisonReturnsNullopt)
{
    const auto patternMatch = PatternMatches("match", "n:^\\*.*soft.*nofile\\s+(\\d+) compare >= asdf");
    ASSERT_FALSE(patternMatch.has_value());
}

TEST(PatternMatchesTest, InvalidPCRE2RegexReturnsNullopt)
{
    const auto patternMatch = PatternMatches("aaaaaaaaaaaaaaaaaaaaa!", "r:^((a+)+$");
    ASSERT_FALSE(patternMatch.has_value());
}

TEST(PatternMatchesTest, SimpleMatch)
{
    auto patternMatch = PatternMatches("match", "match");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
    patternMatch = PatternMatches("nope", "match");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, RegexMatch)
{
    auto patternMatch = PatternMatches("123", "r:\\d+");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
    patternMatch = PatternMatches("abc", "r:\\d+");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, NumericComparison)
{
    auto patternMatch = PatternMatches("123", "n:\\d+ compare == 123");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
    patternMatch = PatternMatches("123", "n:\\d+ compare < 100");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, Negated)
{
    auto patternMatch = PatternMatches("something", "!r:abc");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
    patternMatch = PatternMatches("abc", "!r:abc");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, CompoundPattern)
{
    auto patternMatch = PatternMatches("123abc", "r:\\d+ && r:abc");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);

    patternMatch = PatternMatches("123abc", "r:\\d+ && r:def");
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, EmptyContent)
{
    const auto patternMatch = PatternMatches("", "r:.*");
    if (!patternMatch.has_value())
    {
        // If there's no value, treat it as a failure
        EXPECT_FALSE(true);
    }
    else
    {
        EXPECT_FALSE(*patternMatch);
    }
}

TEST(PatternMatchesTest, DocExample_LineWithoutCommentWithProtocolAnd2)
{
    const std::string content = "Protocol 2";
    const std::string pattern = "!r:^# && r:Protocol && r:2";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, DocExample_CommandOutputStartsWithEnabled)
{
    const std::string content = "enabled";
    const std::string pattern = "r:^enabled";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, DocExample_NumericComparisonMaxAuthTries)
{
    const std::string content = "MaxAuthTries\t3";
    const std::string pattern = "n:^\\s*MaxAuthTries\\s*\\t*(\\d+) compare <= 4";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, DocExample_WholeLineLiteralMatch)
{
    const std::string content = "1";
    const std::string pattern = "1";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, DocExample_NegatedRegexMatch)
{
    const std::string content = "maxauthtries 3";
    const std::string pattern = "!r:^\\s*maxauthtries\\s+4\\s*$";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, DocExample_UIDCheck)
{
    const std::string content = "user:x:0:0";
    const std::string pattern = "!r:^# && !r:^root: && r:^\\w+:\\w+:0:";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, CompoundRule_NegatedCommentAndContainsProtocolAnd2)
{
    const std::string content = "# Some commented line\nProtocol 2\nPort 22";
    const std::string pattern = "!r:^# && r:Protocol && r:2";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, NotRegex_ExcludesMatchingLine)
{
    const std::string content = "PasswordAuthentication yes\nPermitRootLogin yes";
    const std::string pattern = "!r:^PasswordAuthentication\\s+no";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, NotRegex_MatchFailsWhenLineIsPresent)
{
    const std::string content = "PasswordAuthentication no\nPermitRootLogin yes";
    const std::string pattern = "!r:^PasswordAuthentication\\s+no";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, NotRegex_WithCompoundMatch)
{
    const std::string content = "# comment\nPermitRootLogin yes\nPasswordAuthentication yes";
    const std::string pattern = "!r:^# && r:PermitRootLogin && r:yes";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, NotRegex_WithCompoundFailing)
{
    const std::string content = "# PermitRootLogin yes";
    const std::string pattern = "!r:^# && r:PermitRootLogin && r:yes";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_FALSE(*patternMatch);
}

TEST(PatternMatchesTest, MatcherIsCaseInsensitive)
{
    const std::string content = "windows";
    const std::string pattern = "r:^WINDOWS";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

TEST(PatternMatchesTest, REG_MULTI_SZtest)
{
    const std::string content = "some\\string another\\string third\\string yet\\another\\one";
    const std::string pattern = "r:third\\\\string";
    const auto patternMatch = PatternMatches(content, pattern);
    ASSERT_TRUE(patternMatch.has_value());
    EXPECT_TRUE(*patternMatch);
}

// NOLINTEND(bugprone-unchecked-optional-access, modernize-raw-string-literal)


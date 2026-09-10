#include "sca_utils.hpp"
#include <gtest/gtest.h>

#include <json.hpp>

#include "logging_helper.hpp"

using namespace sca;

class ParseRuleTypeTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
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

TEST(SanitizeReasonTest, ValidTextIncludingMultibyteIsUntouched)
{
    const std::string reason = "File '/etc/caf\xc3\xa9.conf' does not exist or is not a regular file";
    EXPECT_EQ(SanitizeReason(reason, 1024), reason);
}

TEST(SanitizeReasonTest, InvalidBytesFromAPathAreReplaced)
{
    // Filenames are arbitrary byte strings, and json::dump() throws on anything not valid UTF-8.
    const auto sanitized = SanitizeReason("Path '/tmp/\xff\xfe' does not exist", 1024);

    EXPECT_EQ(sanitized, "Path '/tmp/\?\?' does not exist");
    EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
}

TEST(SanitizeReasonTest, TruncatedMultibyteSequenceIsReplaced)
{
    const auto sanitized = SanitizeReason("caf\xc3", 1024);

    EXPECT_EQ(sanitized, "caf?");
    EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
}

TEST(SanitizeReasonTest, OversizedReasonIsCutAtTheLastWholeLine)
{
    const std::string reason = "first reason line\nsecond reason line\nthird reason line";

    EXPECT_EQ(SanitizeReason(reason, 30), "first reason line");
}

TEST(SanitizeReasonTest, OversizedSingleLineIsCutOutsideAMultibyteSequence)
{
    // 'é' is two bytes and straddles the cap, so the whole character goes.
    // The literal is split so the hex escape ends: "\xa9f" would be one greedy escape, which
    // GCC truncates with a warning and Clang rejects outright.
    const std::string reason = "abcd\xc3\xa9" "fgh";

    const auto sanitized = SanitizeReason(reason, 5);

    EXPECT_EQ(sanitized, "abcd");
    EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
}

TEST(SanitizeReasonTest, ReasonExactlyAtTheCapIsKept)
{
    const std::string reason(64, 'x');

    EXPECT_EQ(SanitizeReason(reason, 64), reason);
}

TEST(SanitizeReasonTest, OverlongEncodingsAreReplaced)
{
    // Structurally these look like well-formed sequences, but RFC 3629 forbids encoding a code
    // point in more bytes than it needs, and json::dump() rejects them.
    const std::vector<std::pair<std::string, std::string>> cases =
    {
        {"\xC0\xAF", "\?\?"},
        {"\xC1\xBF", "\?\?"},
        {"\xE0\x80\xAF", "\?\?\?"},
        {"\xF0\x80\x80\x80", "\?\?\?\?"},
    };

    for (const auto& [reason, expected] : cases)
    {
        const auto sanitized = SanitizeReason(reason, 1024);

        EXPECT_EQ(sanitized, expected);
        EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
    }
}

TEST(SanitizeReasonTest, SurrogateHalvesAreReplaced)
{
    // U+D800 to U+DFFF only exist to pair up in UTF-16 and are not valid UTF-8.
    const std::vector<std::pair<std::string, std::string>> cases =
    {
        {"\xED\xA0\x80", "\?\?\?"},
        {"\xED\xBF\xBF", "\?\?\?"},
    };

    for (const auto& [reason, expected] : cases)
    {
        const auto sanitized = SanitizeReason(reason, 1024);

        EXPECT_EQ(sanitized, expected);
        EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
    }
}

TEST(SanitizeReasonTest, CodePointsAboveTheUnicodeMaximumAreReplaced)
{
    // Unicode stops at U+10FFFF, so a lead above 0xF4 and 0xF4 followed by more than 0x8F are out.
    const std::vector<std::pair<std::string, std::string>> cases =
    {
        {"\xF5\x80\x80\x80", "\?\?\?\?"},
        {"\xF4\x90\x80\x80", "\?\?\?\?"},
    };

    for (const auto& [reason, expected] : cases)
    {
        const auto sanitized = SanitizeReason(reason, 1024);

        EXPECT_EQ(sanitized, expected);
        EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
    }
}

TEST(SanitizeReasonTest, SequencesAtTheEdgeOfEachRangeAreKept)
{
    // The smallest and largest sequence each range allows, so the added restrictions do not
    // start replacing text that is perfectly valid.
    const std::vector<std::string> valid =
    {
        "\xC2\x80",             // U+0080, smallest two-byte
        "\xDF\xBF",             // U+07FF, largest two-byte
        "\xE0\xA0\x80",         // U+0800, smallest three-byte
        "\xED\x9F\xBF",         // U+D7FF, last before the surrogate block
        "\xEE\x80\x80",         // U+E000, first after the surrogate block
        "\xF0\x90\x80\x80",     // U+10000, smallest four-byte
        "\xF4\x8F\xBF\xBF",     // U+10FFFF, largest code point
    };

    for (const auto& reason : valid)
    {
        EXPECT_EQ(SanitizeReason(reason, 1024), reason);
        EXPECT_NO_THROW(nlohmann::json({{"reason", reason}}).dump());
    }
}

TEST(SanitizeReasonTest, AFilenameCarryingASurrogateIsSafeToSerialise)
{
    // A directory rule quotes the names it reads off disk, which are arbitrary byte strings.
    const auto sanitized = SanitizeReason("Failed to read contents of file '/var/www/\xED\xA0\x80.php'", 1024);

    EXPECT_EQ(sanitized, "Failed to read contents of file '/var/www/\?\?\?.php'");
    EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
}

// NOLINTEND(bugprone-unchecked-optional-access, modernize-raw-string-literal)


#include "sca_reason_sanitizer.hpp"
#include <gtest/gtest.h>

#include <json.hpp>

using namespace sca;

// NOLINTBEGIN(modernize-raw-string-literal)

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

TEST(SanitizeReasonTest, OversizedReasonIsCutAtTheLastWholeLineAndMarked)
{
    const std::string reason = "first line\nsecond line\nthird reason line";

    EXPECT_EQ(SanitizeReason(reason, 35), "first line\nsecond line\n[truncated]");
}

TEST(SanitizeReasonTest, FirstLineAloneIsNotEnoughSoTheSecondIsCutInside)
{
    // A Failed reason starts with a header, and keeping only the header would name no rule.
    const std::string header = "Rules not satisfied (condition 'all'):\n";
    const std::string reason = header + std::string(2000, 'r');

    const auto sanitized = SanitizeReason(reason, 1024);

    EXPECT_EQ(sanitized, header + std::string(1024 - header.size() - 12, 'r') + "\n[truncated]");
}

TEST(SanitizeReasonTest, NoRoomPastTheFirstLineKeepsItWithoutAnEmptyLine)
{
    const std::string reason = "first reason line\nsecond reason line";

    EXPECT_EQ(SanitizeReason(reason, 30), "first reason line\n[truncated]");
}

TEST(SanitizeReasonTest, OversizedSingleLineIsCutOutsideAMultibyteSequenceAndMarked)
{
    // 'é' straddles the room left once the marker is counted, so the whole character goes.
    const std::string reason = "abcdefg\xc3\xa9" "hijklmnopqrstu";

    const auto sanitized = SanitizeReason(reason, 20);

    EXPECT_EQ(sanitized, "abcdefg\n[truncated]");
    EXPECT_NO_THROW(nlohmann::json({{"reason", sanitized}}).dump());
}

TEST(SanitizeReasonTest, CapTooSmallForTheMarkerCutsWithoutIt)
{
    const std::string reason = "first reason line\nsecond reason line";

    EXPECT_EQ(SanitizeReason(reason, 10), "first reas");
}

TEST(SanitizeReasonTest, SanitizingATruncatedReasonAgainChangesNothing)
{
    std::string reason;

    for (int line = 0; line < 100; ++line)
    {
        reason += "f:/etc/ssh/sshd_config -> r:^\\s*Ciphers\n";
    }

    const auto once = SanitizeReason(reason, 1024);

    EXPECT_LE(once.size(), 1024U);
    EXPECT_EQ(SanitizeReason(once, 1024), once);
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

// NOLINTEND(modernize-raw-string-literal)

/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "os_release_parser.hpp"

#include <gtest/gtest.h>

#include <json.hpp>

#include <string>

using namespace containerimages;

namespace
{
    // Real os-release files of the images the inventory meets most.
    const std::string DEBIAN
    {
        "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
        "NAME=\"Debian GNU/Linux\"\n"
        "VERSION_ID=\"12\"\n"
        "VERSION=\"12 (bookworm)\"\n"
        "VERSION_CODENAME=bookworm\n"
        "ID=debian\n"
        "HOME_URL=\"https://www.debian.org/\"\n"
        "SUPPORT_URL=\"https://www.debian.org/support\"\n"
        "BUG_REPORT_URL=\"https://bugs.debian.org/\"\n"};

    const std::string UBUNTU
    {
        "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"
        "NAME=\"Ubuntu\"\n"
        "VERSION_ID=\"24.04\"\n"
        "VERSION=\"24.04.1 LTS (Noble Numbat)\"\n"
        "VERSION_CODENAME=noble\n"
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        "UBUNTU_CODENAME=noble\n"};

    const std::string ALPINE
    {
        "NAME=\"Alpine Linux\"\n"
        "ID=alpine\n"
        "VERSION_ID=3.19.1\n"
        "PRETTY_NAME=\"Alpine Linux v3.19\"\n"
        "HOME_URL=\"https://alpinelinux.org/\"\n"
        "BUG_REPORT_URL=\"https://gitlab.alpinelinux.org/alpine/aports/-/issues\"\n"};

    const std::string UBI
    {
        "NAME=\"Red Hat Enterprise Linux\"\n"
        "VERSION=\"9.3 (Plow)\"\n"
        "ID=\"rhel\"\n"
        "ID_LIKE=\"fedora\"\n"
        "VERSION_ID=\"9.3\"\n"
        "PLATFORM_ID=\"platform:el9\"\n"
        "PRETTY_NAME=\"Red Hat Enterprise Linux 9.3 (Plow)\"\n"};
}

TEST(OsReleaseParserTest, ReadsADebianImage)
{
    const auto os {parseOsRelease(DEBIAN)};

    EXPECT_EQ(os.name, "Debian GNU/Linux");
    EXPECT_EQ(os.version, "12");
    EXPECT_EQ(os.id, "debian");
    EXPECT_EQ(os.codename, "bookworm");
    EXPECT_EQ(os.prettyName, "Debian GNU/Linux 12 (bookworm)");
    EXPECT_TRUE(os.family.empty());
}

TEST(OsReleaseParserTest, ReadsTheFamilyOfADerivative)
{
    const auto os {parseOsRelease(UBUNTU)};

    EXPECT_EQ(os.id, "ubuntu");
    EXPECT_EQ(os.family, "debian");
    EXPECT_EQ(os.version, "24.04");
    EXPECT_EQ(os.codename, "noble");
}

TEST(OsReleaseParserTest, ReadsAnAlpineImageThatHasNoCodename)
{
    const auto os {parseOsRelease(ALPINE)};

    EXPECT_EQ(os.name, "Alpine Linux");
    EXPECT_EQ(os.version, "3.19.1");
    EXPECT_EQ(os.id, "alpine");
    EXPECT_EQ(os.prettyName, "Alpine Linux v3.19");
    EXPECT_TRUE(os.codename.empty());
    EXPECT_TRUE(os.family.empty());
}

TEST(OsReleaseParserTest, ReadsAUniversalBaseImage)
{
    const auto os {parseOsRelease(UBI)};

    EXPECT_EQ(os.name, "Red Hat Enterprise Linux");
    EXPECT_EQ(os.version, "9.3");
    EXPECT_EQ(os.id, "rhel");
    EXPECT_EQ(os.family, "fedora");
    EXPECT_EQ(os.prettyName, "Red Hat Enterprise Linux 9.3 (Plow)");
}

TEST(OsReleaseParserTest, TheFamilyIsTheFirstWordOfIdLike)
{
    EXPECT_EQ(parseOsRelease("ID=centos\nID_LIKE=\"rhel fedora\"\n").family, "rhel");
    EXPECT_EQ(parseOsRelease("ID=x\nID_LIKE=\"  suse\topensuse\"\n").family, "suse");
}

TEST(OsReleaseParserTest, ContentWithNoRecognizedKeyIsEmpty)
{
    EXPECT_TRUE(parseOsRelease("").empty());
    EXPECT_TRUE(parseOsRelease("\n\n").empty());
    EXPECT_TRUE(parseOsRelease("HOME_URL=\"https://example.invalid\"\n").empty());
}

TEST(OsReleaseParserTest, CommentsBlankLinesAndMalformedLinesAreSkipped)
{
    const auto os {parseOsRelease("# a comment\n"
                                  "\n"
                                  "   # an indented comment\n"
                                  "not a key value line\n"
                                  "=no key\n"
                                  "ID=debian\n"
                                  "NAME\n")};

    EXPECT_EQ(os.id, "debian");
    EXPECT_TRUE(os.name.empty());
}

TEST(OsReleaseParserTest, QuotingFollowsTheShellRules)
{
    const auto os {parseOsRelease("NAME='single \"quoted\"'\n"
                                  "PRETTY_NAME=\"say \\\"hi\\\" \\$HOME\"\n"
                                  "ID=bare\n")};

    EXPECT_EQ(os.name, "single \"quoted\"");
    EXPECT_EQ(os.prettyName, "say \"hi\" $HOME");
    EXPECT_EQ(os.id, "bare");
}

TEST(OsReleaseParserTest, WindowsLineEndingsAreTolerated)
{
    const auto os {parseOsRelease("ID=debian\r\nVERSION_ID=\"12\"\r\n")};

    EXPECT_EQ(os.id, "debian");
    EXPECT_EQ(os.version, "12");
}

TEST(OsReleaseParserTest, TheLastAssignmentOfAKeyWins)
{
    EXPECT_EQ(parseOsRelease("ID=first\nID=second\n").id, "second");
}

TEST(OsReleaseParserTest, ALineWithNoTrailingNewlineIsRead)
{
    EXPECT_EQ(parseOsRelease("ID=debian").id, "debian");
}

TEST(OsReleaseParserTest, AnUnterminatedQuoteIsKeptAsWritten)
{
    EXPECT_EQ(parseOsRelease("NAME=\"broken\n").name, "\"broken");
}

TEST(OsReleaseParserTest, BinaryGarbageDoesNotThrow)
{
    const std::string garbage {"\x00\xff\xfe=\x01\n\x80=\"\n=\n", 12};

    EXPECT_NO_THROW(parseOsRelease(garbage));
}

TEST(OsReleaseParserTest, TheLocationsAreTheEtcFileThenTheUsrFallback)
{
    EXPECT_EQ(osReleasePaths(), std::vector<std::string>({"etc/os-release", "usr/lib/os-release"}));
}

TEST(OsReleaseParserTest, InvalidUtf8IsReplacedSoTheValuesCanBeStored)
{
    // Latin-1 "Café", a lone continuation byte, a truncated sequence, an overlong slash and a surrogate.
    const auto os {parseOsRelease("NAME=\"Caf\xE9\"\n"
                                  "ID=a\x80z\n"
                                  "VERSION_ID=\"1\xE2\x82\"\n"
                                  "PRETTY_NAME=\"\xC0\xAF|\xED\xA0\x80\"\n")};

    EXPECT_EQ(os.name, "Caf\xEF\xBF\xBD");
    EXPECT_EQ(os.id, "a\xEF\xBF\xBDz");
    EXPECT_EQ(os.version, "1\xEF\xBF\xBD\xEF\xBF\xBD");
    EXPECT_EQ(os.prettyName, "\xEF\xBF\xBD\xEF\xBF\xBD|\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");

    // What matters downstream: every parsed value serializes to JSON.
    const std::vector<std::string> values {os.name, os.id, os.version, os.prettyName};

    for (const auto& value : values)
    {
        EXPECT_NO_THROW(nlohmann::json(value).dump()) << value;
    }
}

TEST(OsReleaseParserTest, ValidMultiByteUtf8IsKept)
{
    EXPECT_EQ(parseOsRelease("NAME=\"Caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x90\xA7\"\n").name,
              "Caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x90\xA7");
}

TEST(OsReleaseParserTest, ATrailingCommentAfterTheClosingQuoteIsIgnored)
{
    EXPECT_EQ(parseOsRelease("NAME=\"Debian\" # the name\n").name, "Debian");
    EXPECT_EQ(parseOsRelease("NAME='Debian'#x\n").name, "Debian");
}

TEST(OsReleaseParserTest, TextAfterTheClosingQuoteThatIsNotACommentKeepsTheValueAsWritten)
{
    EXPECT_EQ(parseOsRelease("NAME=\"a\"b\n").name, "\"a\"b");
}

TEST(OsReleaseParserTest, AByteOrderMarkDoesNotHideTheFirstKey)
{
    const auto os {parseOsRelease("\xEF\xBB\xBFID=debian\nVERSION_ID=12\n")};

    EXPECT_EQ(os.id, "debian");
    EXPECT_EQ(os.version, "12");
}

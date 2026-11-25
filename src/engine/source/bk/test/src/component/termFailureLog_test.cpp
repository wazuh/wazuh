// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include <base/json.hpp>
#include <base/logging.hpp>

#include <termFailureLog.hpp>

using namespace bk::detail;

TEST(TermFailureLog, TextIsCutAndKeptOnOneLine)
{
    EXPECT_EQ(termFailureText("plain text"), "plain text");
    EXPECT_EQ(termFailureText(std::string {"a\nb\rc\td\x7f"} + "e"), "a b c d e");
    EXPECT_EQ(termFailureText(std::string(TERM_FAILURE_WHAT_MAX + 100, 'x')), std::string(TERM_FAILURE_WHAT_MAX, 'x'));
    EXPECT_EQ(termFailureText(""), "");

    // A character the limit would split is left out whole
    const auto split = std::string(TERM_FAILURE_WHAT_MAX - 1, 'x') + "\xC3\xA9";
    EXPECT_EQ(termFailureText(split), std::string(TERM_FAILURE_WHAT_MAX - 1, 'x'));
}

TEST(TermFailureLog, RepeatedFailuresAreReportedWithoutThrowing)
{
    logging::testInit();
    const auto event = std::make_shared<json::Json>(R"({"key":"value"})");

    for (auto i = 0; i < 1000; ++i)
    {
        EXPECT_NO_THROW(logTermFailure("term", "error\nwith a line break", event));
    }
}

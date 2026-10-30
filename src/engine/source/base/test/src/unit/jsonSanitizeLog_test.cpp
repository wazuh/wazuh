// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/logCapture.hpp>
#include <base/logging.hpp>

namespace
{
// The byte 0xFF never appears in valid UTF-8, so the writer cannot serialize a document holding it
// and Json::str() takes the sanitizing pass that logs.
const std::string INVALID_VALUE = std::string {"hunter2"} + static_cast<char>(0xFF);
constexpr auto FIELD_NAME {"credential"};
constexpr auto REPLACEMENT_CHAR {"\xEF\xBF\xBD"}; // U+FFFD, what the invalid byte becomes

// Both summary lines of the sanitizing pass open with this; the other messages of the module, the
// collision debug among them, do not, and they would throw the exact counts below off.
constexpr auto SANITIZE_PREFIX {"[Json] Serialized a document with invalid UTF-8 or a non-finite number"};

// The summary lines of the sanitizing pass at a given level, which is what this test asserts on;
// anything else the engine logs while the test runs is not its business.
std::vector<std::string> jsonMessages(const base::test::LogCapture& capture, logging::Level level)
{
    std::vector<std::string> messages;
    for (const auto& record : capture.records(level))
    {
        if (record.message.rfind(SANITIZE_PREFIX, 0) == 0)
        {
            messages.push_back(record.message);
        }
    }

    return messages;
}
} // namespace

// Which occurrence is the first one is process-global state (g_sanitizedOnce in json.cpp), so the
// whole sequence runs in a single case, in a binary of its own: any other case serializing an
// invalid document first would take the warning away from this one.
TEST(JsonSanitizeLog, WarnsOnceThenDebugsAndNeverLogsTheEvent)
{
    base::test::LogCapture capture {logging::Level::Debug};

    json::Json doc;
    doc.setString(INVALID_VALUE, std::string {"/"} + FIELD_NAME);

    const auto first = doc.str();

    // The writer targets ASCII, so the output carries the replacement escaped; the document it
    // re-parses to is where the character itself shows up, which is what says the pass ran.
    std::optional<json::Json> parsed;
    ASSERT_NO_THROW(parsed.emplace(first)) << first;
    std::string sanitized;
    ASSERT_EQ(json::RetGet::Success, parsed->getString(sanitized, std::string {"/"} + FIELD_NAME));
    ASSERT_NE(sanitized.find(REPLACEMENT_CHAR), std::string::npos) << "the document did not take the sanitizing pass";

    const auto firstWarnings = jsonMessages(capture, logging::Level::Warn);
    ASSERT_EQ(firstWarnings.size(), 1u);
    EXPECT_TRUE(jsonMessages(capture, logging::Level::Debug).empty());

    const auto firstRecords = capture.records();
    capture.clear();

    const auto second = doc.str();
    ASSERT_EQ(second, first);

    EXPECT_TRUE(jsonMessages(capture, logging::Level::Warn).empty());
    const auto secondDebugs = jsonMessages(capture, logging::Level::Debug);
    ASSERT_EQ(secondDebugs.size(), 1u);

    // No line carries the document: not the field name, not its value, not the invalid byte and not
    // the sanitized output either. A log of an event is a log of whatever the agent sent, so the check
    // runs over every record of both serializations, not only the two summary lines: a leak added
    // anywhere else in the sanitizing pass is the same leak.
    auto allRecords = firstRecords;
    const auto secondRecords = capture.records();
    allRecords.insert(allRecords.end(), secondRecords.begin(), secondRecords.end());
    ASSERT_FALSE(allRecords.empty());

    for (const auto& record : allRecords)
    {
        const auto& message = record.message;
        EXPECT_EQ(message.find(FIELD_NAME), std::string::npos) << message;
        EXPECT_EQ(message.find("hunter2"), std::string::npos) << message;
        EXPECT_EQ(message.find(static_cast<char>(0xFF)), std::string::npos) << message;
        EXPECT_EQ(message.find(REPLACEMENT_CHAR), std::string::npos) << message;
        EXPECT_EQ(message.find(first), std::string::npos) << message;
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

#include <base/eventParser.hpp>

namespace
{

struct EventParserParam
{
    std::string input;
    std::string agentMetadata;
    std::optional<std::string> expectedEvent;
};

class EventParserTest : public ::testing::TestWithParam<EventParserParam>
{
};

TEST_P(EventParserTest, ParseLegacyEvent)
{
    namespace ep = base::eventParsers;
    auto param = GetParam();

    try
    {
        json::Json agentMetadata(param.agentMetadata);
        auto event = ep::parseLegacyEvent(param.input, agentMetadata);
        ASSERT_TRUE(param.expectedEvent.has_value());

        json::Json expectedEvent(param.expectedEvent.value());

        EXPECT_EQ(*event, expectedEvent) << "Parsed event does not match expected event.\nParsed: " << event->str()
                                         << "\nExpected: " << expectedEvent.str();
    }
    catch (const std::runtime_error& e)
    {
        ASSERT_FALSE(param.expectedEvent.has_value()) << "Unexpected exception: " << e.what();
    }
}

INSTANTIATE_TEST_SUITE_P(
    ParseLegacyEventRawLocation,
    EventParserTest,
    ::testing::Values(
        EventParserParam {
            "0:location:message",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":48,"location":"location"}},"agent":{"name":"test"},"event":{"original":"message"}})"},
        EventParserParam {
            "1:2:3",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"2"}},"agent":{"name":"test"},"event":{"original":"3"}})"},
        EventParserParam {
            "1:2:3:",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"2"}},"agent":{"name":"test"},"event":{"original":"3:"}})"},
        EventParserParam {
            "1:2::3:",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"2"}},"agent":{"name":"test"},"event":{"original":":3:"}})"},
        EventParserParam {
            "1:2|::3:",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"2:"}},"agent":{"name":"test"},"event":{"original":"3:"}})"},
        EventParserParam {
            "1:2||::3:",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"2|:"}},"agent":{"name":"test"},"event":{"original":"3:"}})"},
        EventParserParam {
            "1:||2|||::3:",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"||2||:"}},"agent":{"name":"test"},"event":{"original":"3:"}})"},
        EventParserParam {
            "1:001|:0db8|:85a3|:0000|:0000|:8a2e|:0370|:7334:3",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"001:0db8:85a3:0000:0000:8a2e:0370:7334"}},"agent":{"name":"test"},"event":{"original":"3"}})"},
        EventParserParam {
            "1:|:|:ffff|:0.0.0.0:3",
            R"({"agent":{"name":"test"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"::ffff:0.0.0.0"}},"agent":{"name":"test"},"event":{"original":"3"}})"},
        // Empty agent metadata
        EventParserParam {
            "1:loc:msg", R"({})", R"({"wazuh":{"protocol":{"queue":49,"location":"loc"}},"event":{"original":"msg"}})"},
        // Agent metadata with extra fields
        EventParserParam {
            "1:loc:msg",
            R"({"agent":{"name":"test"},"extra":{"field":"value"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"loc"}},"agent":{"name":"test"},"extra":{"field":"value"},"event":{"original":"msg"}})"},
        // Invalid format
        EventParserParam {"", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {":", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"::", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {":::", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"1", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"1:", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"1:2", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"1:2:", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"1::3", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {":2:3", R"({"agent":{"name":"test"}})", std::nullopt},
        EventParserParam {"::3", R"({"agent":{"name":"test"}})", std::nullopt},
        // Highest queue byte the indexer stores (signed byte)
        EventParserParam {"\x7F:loc:msg",
                          R"({})",
                          R"({"wazuh":{"protocol":{"queue":127,"location":"loc"}},"event":{"original":"msg"}})"},
        // Lowest queue byte accepted
        EventParserParam {"\x01:loc:msg",
                          R"({})",
                          R"({"wazuh":{"protocol":{"queue":1,"location":"loc"}},"event":{"original":"msg"}})"},
        // Queue byte 0x00 is refused, as /logtest refuses queue 0
        EventParserParam {std::string("\0:loc:msg", 9), R"({})", std::nullopt},
        // Queue bytes above 0x7F are refused
        EventParserParam {"\x80:loc:msg", R"({})", std::nullopt},
        EventParserParam {"\xC3:loc:msg", R"({})", std::nullopt},
        EventParserParam {"\xFF:loc:msg", R"({})", std::nullopt}));

INSTANTIATE_TEST_SUITE_P(
    ParseLegacyEventWithAgent,
    EventParserTest,
    ::testing::Values(
        // Single-char ID, simple name and module
        EventParserParam {
            "1:[A] (Alice) any->home:Hello",
            R"({"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"}})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"[A] (Alice) any->home"}},"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"},"event":{"original":"Hello"}})"},
        // Multi-char ID and name containing spaces
        EventParserParam {
            "7:[xyz123] (Bob Marley) 1.1.1.1->dashboard:LogIn",
            R"({"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"}})",
            R"({"wazuh":{"protocol":{"queue":55,"location":"[xyz123] (Bob Marley) 1.1.1.1->dashboard"}},"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"},"event":{"original":"LogIn"}})"},
        // Module and message may contain colons
        EventParserParam {
            "9:[ID42] (Agent|:007) |:|:1->server|:port:Payload:data",
            R"({"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"}})",
            R"({"wazuh":{"protocol":{"queue":57,"location":"[ID42] (Agent:007) ::1->server:port"}},"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"},"event":{"original":"Payload:data"}})"},
        // Edge case: name with arrow-like substring but only first “->” is parsed
        EventParserParam {
            "5:[007] (E>X) a->sys->err:Okay",
            R"({"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"}})",
            R"({"wazuh":{"protocol":{"queue":53,"location":"[007] (E>X) a->sys->err"}},"agent":{"name":"dummy-agent-name","id":"dummy-agent-id"},"event":{"original":"Okay"}})"},
        // Legacy location with empty agent metadata
        EventParserParam {
            "1:[A] (Alice) any->home:Hello",
            R"({})",
            R"({"wazuh":{"protocol":{"queue":49,"location":"[A] (Alice) any->home"}},"event":{"original":"Hello"}})"}));

/// Returns the what() of the runtime_error thrown by parseLegacyEvent, or "" when nothing is thrown.
std::string legacyParseError(std::string_view input)
{
    try
    {
        base::eventParsers::parseLegacyEvent(input, json::Json(R"({})"));
    }
    catch (const std::runtime_error& e)
    {
        return e.what();
    }
    return {};
}

// The reported reason must match the actual defect of the line.
TEST(EventParserReasonTest, ShortLineReportsLength)
{
    EXPECT_NE(legacyParseError("1:a").find("at least 5 bytes"), std::string::npos);
}

TEST(EventParserReasonTest, LongLineWithoutQueueSeparatorReportsMissingSeparator)
{
    const auto reason = legacyParseError("this is not a wazuh event");
    EXPECT_EQ(reason.find("at least 5 bytes"), std::string::npos) << reason;
    EXPECT_NE(reason.find("missing ':' after the one-byte queue identifier"), std::string::npos) << reason;
}

TEST(EventParserReasonTest, MissingLocationSeparatorIsReported)
{
    EXPECT_NE(legacyParseError("1:location-without-message").find("missing unescaped ':'"), std::string::npos);
}

TEST(EventParserReasonTest, QueueByteAbove7FIsReported)
{
    const auto reason = legacyParseError("\xC3:location:message");
    EXPECT_NE(reason.find("queue identifier 0xC3 is outside 0x01..0x7F"), std::string::npos) << reason;
}

} // namespace

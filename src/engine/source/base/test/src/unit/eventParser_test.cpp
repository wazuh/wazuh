#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

#include <base/eventParser.hpp>

namespace
{

/*
Test fixture for testing the EventParser
Tuple:
- Input string (Wazuh legacy message)
- Output: queue, location, message (int, string, string) or empty if an exception is thrown
*/
class EventParserRawLocationParamTest
    : public ::testing::TestWithParam<std::pair<std::string, std::optional<std::tuple<int, std::string, std::string>>>>
{
};

// Test cases for the EventParser
TEST_P(EventParserRawLocationParamTest, ParseLegacyEvent)
{
    namespace ep = base::eventParsers;
    auto [input, expected] = GetParam();

    try
    {
        auto event = ep::parseLegacyEvent(std::move(input));
        ASSERT_TRUE(expected.has_value());
        auto eventQueueId = event->getInt(ep::EVENT_QUEUE_ID);
        auto eventLocation = event->getString(ep::EVENT_LOCATION_ID);
        auto eventMessage = event->getString(ep::EVENT_MESSAGE_ID);
        ASSERT_TRUE(eventQueueId.has_value()) << "Expected queue ID to be present";
        ASSERT_TRUE(eventLocation.has_value()) << "Expected location to be present";
        ASSERT_TRUE(eventMessage.has_value()) << "Expected message to be present";

        ASSERT_EQ(eventQueueId.value(), std::get<0>(expected.value())) << "Queue ID does not match expected value";
        ASSERT_EQ(eventLocation.value(), std::get<1>(expected.value())) << "Location does not match expected value";
        ASSERT_EQ(eventMessage.value(), std::get<2>(expected.value())) << "Message does not match expected value";
    }
    catch (const std::runtime_error& e)
    {
        ASSERT_FALSE(expected.has_value()) << "Unexpected exception: " << e.what();
    }
}

INSTANTIATE_TEST_SUITE_P(
    ParseLegacyEvent,
    EventParserRawLocationParamTest,
    ::testing::Values(
        std::make_pair("0:location:message", std::make_optional(std::make_tuple(48, "location", "message"))),
        std::make_pair("1:2:3", std::make_optional(std::make_tuple(49, "2", "3"))),
        std::make_pair("1:2:3:", std::make_optional(std::make_tuple(49, "2", "3:"))),
        std::make_pair("1:2::3:", std::make_optional(std::make_tuple(49, "2", ":3:"))),
        std::make_pair("1:2|::3:", std::make_optional(std::make_tuple(49, "2:", "3:"))),
        std::make_pair("1:2||::3:", std::make_optional(std::make_tuple(49, "2|:", "3:"))),
        std::make_pair("1:||2|||::3:", std::make_optional(std::make_tuple(49, "||2||:", "3:"))),
        std::make_pair("1:001|:0db8|:85a3|:0000|:0000|:8a2e|:0370|:7334:3",
                       std::make_optional(std::make_tuple(49, "001:0db8:85a3:0000:0000:8a2e:0370:7334", "3"))),
        std::make_pair("1:2:3", std::make_optional(std::make_tuple(49, "2", "3"))),
        std::make_pair("1:|:|:ffff|:0.0.0.0:3", std::make_optional(std::make_tuple(49, "::ffff:0.0.0.0", "3"))),
        // Invalid format
        std::make_pair("", std::nullopt),
        std::make_pair(":", std::nullopt),
        std::make_pair("::", std::nullopt),
        std::make_pair(":::", std::nullopt),
        std::make_pair("1", std::nullopt),
        std::make_pair("1:", std::nullopt),
        std::make_pair("1:2", std::nullopt),
        std::make_pair("1:2:", std::nullopt),
        std::make_pair("1::3", std::nullopt),
        std::make_pair(":2:3", std::nullopt),
        std::make_pair("::3", std::nullopt)));

/*
Test fixture for legacy-location prefix cases
 Tuple:
 - Input string (Wazuh legacy message including “[ID] Name->Module” in location)
 - Expected: queue, module, message, agentID, agentName
*/

struct LegacyLocationParam
{
    std::string input;
    int expectedQueue;
    std::string expectedModule;
    std::string expectedMessage;
    std::string expectedAgentID;
    std::string expectedAgentName;
};

class EventParserLegacyLocationParamTest : public ::testing::TestWithParam<LegacyLocationParam>
{
};

TEST_P(EventParserLegacyLocationParamTest, ParseLegacyEvent_WithAgentInfo)
{
    namespace ep = base::eventParsers;
    auto param = GetParam();

    // Call parseLegacyEvent
    auto event = ep::parseLegacyEvent(std::move(param.input));

    // Verify queue, module (location), and message
    auto eventQueueId = event->getInt(ep::EVENT_QUEUE_ID);
    auto eventLocation = event->getString(ep::EVENT_LOCATION_ID);
    auto eventMessage = event->getString(ep::EVENT_MESSAGE_ID);
    ASSERT_TRUE(eventQueueId.has_value());
    ASSERT_TRUE(eventLocation.has_value());
    ASSERT_TRUE(eventMessage.has_value());

    EXPECT_EQ(eventQueueId.value(), param.expectedQueue);
    EXPECT_EQ(eventLocation.value(), param.expectedModule);
    EXPECT_EQ(eventMessage.value(), param.expectedMessage);

    // Verify agentID and agentName in the JSON
    auto agentID = event->getString(ep::EVENT_AGENT_ID);
    auto agentName = event->getString(ep::EVENT_AGENT_NAME);
    ASSERT_TRUE(agentID.has_value());
    ASSERT_TRUE(agentName.has_value());

    EXPECT_EQ(agentID.value(), param.expectedAgentID);
    EXPECT_EQ(agentName.value(), param.expectedAgentName);
}

INSTANTIATE_TEST_SUITE_P(
    ParseLegacyEventWithAgent,
    EventParserLegacyLocationParamTest,
    ::testing::Values(
        // Single-char ID, simple name and module
        LegacyLocationParam {
            "1:[A] Alice->home:Hello",
            49,      // '1' as unsigned char
            "home",  // module
            "Hello", // message
            "A",     // agentID
            "Alice"  // agentName
        },
        // Multi-char ID and name containing spaces
        LegacyLocationParam {
            "7:[xyz123] Bob Marley->dashboard:LogIn", 55, "dashboard", "LogIn", "xyz123", "Bob Marley"},
        // Module and message may contain colons
        LegacyLocationParam {"9:[ID42] Agent|:007->server|:port:Payload:data",
                             57,
                             "server:port",  // module includes a colon
                             "Payload:data", // message includes a colon
                             "ID42",
                             "Agent:007"},
        // Edge case: name with arrow-like substring but only first “->” is parsed
        LegacyLocationParam {"5:[007] E>X->sys->err:Okay",
                             53,
                             "sys->err", // module contains “->” after the first
                             "Okay",
                             "007",
                             "E>X"}));
} // namespace

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

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0)
    {
        throw std::runtime_error("Failed to get hostname");
    }
    std::string hostNameStr(hostname);

    try
    {
        auto event = ep::parseLegacyEvent(input);
        ASSERT_TRUE(expected.has_value());
        auto eventQueueId = event->getInt(ep::EVENT_QUEUE_ID);
        auto eventLocation = event->getString(ep::EVENT_LOCATION_ID);
        auto eventMessage = event->getString(ep::EVENT_MESSAGE_ID);
        auto eventAgentId = event->getString(ep::EVENT_AGENT_ID);
        auto eventAgentName = event->getString(ep::EVENT_AGENT_NAME);
        auto eventManagerName = event->getString(ep::EVENT_MANAGER_NAME);
        ASSERT_TRUE(eventQueueId.has_value()) << "Expected queue ID to be present";
        ASSERT_TRUE(eventLocation.has_value()) << "Expected location to be present";
        ASSERT_TRUE(eventMessage.has_value()) << "Expected message to be present";
        ASSERT_TRUE(eventAgentId.has_value()) << "Expected agent ID to be present";
        ASSERT_TRUE(eventAgentName.has_value()) << "Expected agent name to be present";
        ASSERT_TRUE(eventManagerName.has_value()) << "Expected manager name to be present";

        ASSERT_EQ(eventQueueId.value(), std::get<0>(expected.value())) << "Queue ID does not match expected value";
        ASSERT_EQ(eventLocation.value(), std::get<1>(expected.value())) << "Location does not match expected value";
        ASSERT_EQ(eventMessage.value(), std::get<2>(expected.value())) << "Message does not match expected value";
        ASSERT_EQ(eventAgentId.value(), "000") << "Agent ID does not match expected value";
        ASSERT_EQ(eventAgentName.value(), hostNameStr) << "Agent name does not match expected value";
        ASSERT_EQ(eventManagerName.value(), hostNameStr) << "Manager name does not match expected value";
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
 - Input string (Wazuh legacy message including “[ID] (Name) ip->Module” in location)
 - Expected: queue, module, message, agentID, agentName
*/

struct LegacyLocationParam
{
    std::string_view input;
    int expectedQueue;
    std::string expectedModule;
    std::string expectedMessage;
    std::string expectedAgentID;
    std::string expectedAgentName;
    std::string expectedRegisterIP;
};

class EventParserLegacyLocationParamTest : public ::testing::TestWithParam<LegacyLocationParam>
{
};

TEST_P(EventParserLegacyLocationParamTest, ParseLegacyEvent_WithAgentInfo)
{
    namespace ep = base::eventParsers;
    auto param = GetParam();

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0)
    {
        throw std::runtime_error("Failed to get hostname");
    }
    std::string hostNameStr(hostname);

    // Call parseLegacyEvent
    auto event = ep::parseLegacyEvent(param.input);

    // Verify queue, module (location), and message
    auto eventQueueId = event->getInt(ep::EVENT_QUEUE_ID);
    auto eventLocation = event->getString(ep::EVENT_LOCATION_ID);
    auto eventMessage = event->getString(ep::EVENT_MESSAGE_ID);
    auto eventManagerName = event->getString(ep::EVENT_MANAGER_NAME);

    ASSERT_TRUE(eventQueueId.has_value());
    ASSERT_TRUE(eventLocation.has_value());
    ASSERT_TRUE(eventMessage.has_value());

    EXPECT_EQ(eventQueueId.value(), param.expectedQueue);
    EXPECT_EQ(eventLocation.value(), param.expectedModule);
    EXPECT_EQ(eventMessage.value(), param.expectedMessage);

    // Verify manager_name agentID and agentName in the JSON
    auto agentID = event->getString(ep::EVENT_AGENT_ID);
    auto agentName = event->getString(ep::EVENT_AGENT_NAME);
    auto managerName = event->getString(ep::EVENT_MANAGER_NAME);
    ASSERT_TRUE(managerName.has_value());
    ASSERT_EQ(managerName.value(), hostNameStr) << "Manager name does not match expected hostname";

    ASSERT_TRUE(agentID.has_value());
    ASSERT_TRUE(agentName.has_value());

    EXPECT_EQ(agentID.value(), param.expectedAgentID) << "Agent ID does not match expected value";
    EXPECT_EQ(agentName.value(), param.expectedAgentName) << "Agent name does not match expected value";
}

INSTANTIATE_TEST_SUITE_P(ParseLegacyEventWithAgent,
                         EventParserLegacyLocationParamTest,
                         ::testing::Values(
                             // Single-char ID, simple name and module
                             LegacyLocationParam {
                                 "1:[A] (Alice) any->home:Hello",
                                 49,      // '1' as unsigned char
                                 "home",  // module
                                 "Hello", // message
                                 "A",     // agentID
                                 "Alice", // agentName
                                 "any"    // registerIP
                             },
                             // Multi-char ID and name containing spaces
                             LegacyLocationParam {"7:[xyz123] (Bob Marley) 1.1.1.1->dashboard:LogIn",
                                                  55,
                                                  "dashboard",
                                                  "LogIn",
                                                  "xyz123",
                                                  "Bob Marley",
                                                  "1.1.1.1"},
                             // Module and message may contain colons
                             LegacyLocationParam {"9:[ID42] (Agent|:007) |:|:1->server|:port:Payload:data",
                                                  57,
                                                  "server:port",  // module includes a colon
                                                  "Payload:data", // message includes a colon
                                                  "ID42",
                                                  "Agent:007",
                                                  "::1"},
                             // Edge case: name with arrow-like substring but only first “->” is parsed
                             LegacyLocationParam {"5:[007] (E>X) a->sys->err:Okay",
                                                  53,
                                                  "sys->err", // module contains “->” after the first
                                                  "Okay",
                                                  "007",
                                                  "E>X",
                                                  "a"}));
} // namespace

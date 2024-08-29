#include <string>

#include <gtest/gtest.h>

#include <base/parseEvent.hpp>

constexpr char TEST_QUEUE_ID {0x01};
constexpr char TEST_AGENT_ID[] {"404"};
constexpr char TEST_AGENT_NAME[] {"testAgentName"};
constexpr char TEST_AGENT_REGISTEREDIP_TXT[] {"testTxtIP"};
constexpr char TEST_ORIGINAL_ROUTE[] {"/test/Route"};
constexpr char TEST_IPV4[] {"1.205.0.44"};
constexpr char TEST_EXTENDED_IPV6[] {R"(ABCD|:EFG0|:1234|:5678|:0009|:00AB|:00C6|:0D7B)"};
constexpr char TEST_EXTENDED_IPV6_UNESCAPED[] {R"(ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B)"};
constexpr char TEST_ORIGINAL_LOG[] {"Testing -> log : containing ([)] symbols."};
constexpr char TEST_ESCAPED_COMMAND[] {"command 1|:2 arg"};
constexpr char TEST_UNESCAPED_COMMAND[] {"command 1:2 arg"};

#define GTEST_CASE "[ USE CASE ] "

struct UseCase
{
    std::string description;
    char queue;
    std::string location;
    std::string log;
    std::string unescapeLocation;
};

void execute(const UseCase& useCase)
{
    const std::string event {std::string {} + useCase.queue + ":" + useCase.location + ":" + useCase.log};

    auto e = base::parseEvent::parseWazuhEvent(event);

    auto parsedQueue = e->getInt(base::parseEvent::EVENT_QUEUE_ID);
    EXPECT_EQ(parsedQueue.value(), int(useCase.queue)) << GTEST_CASE << useCase.description;

    auto parsedLocation = e->getString(base::parseEvent::EVENT_LOCATION_ID);
    if (!useCase.unescapeLocation.empty())
    {
        EXPECT_STREQ(parsedLocation.value().c_str(), useCase.unescapeLocation.c_str())
            << GTEST_CASE << useCase.description;
    }
    else
    {
        EXPECT_STREQ(parsedLocation.value().c_str(), useCase.location.c_str()) << GTEST_CASE << useCase.description;
    }

    auto parsedMessage = e->getString(base::parseEvent::EVENT_MESSAGE_ID);
    EXPECT_STREQ(parsedMessage.value().c_str(), useCase.log.c_str()) << GTEST_CASE << useCase.description;
}

TEST(parseWazuhEvent, InvalidEventFormat)
{
    const std::string event {"Invalid event format string"};
    ASSERT_THROW(base::parseEvent::parseWazuhEvent(event), std::runtime_error);
}

TEST(parseWazuhEvent, InvalidShortEvent)
{
    const std::string event {"x::"};
    ASSERT_THROW(base::parseEvent::parseWazuhEvent(event), std::runtime_error);
}

TEST(parseWazuhEvent, Forms)
{
    std::vector<UseCase> useCases = {
        UseCase {"FormI",
                 TEST_QUEUE_ID,
                 std::string {} + "[" + TEST_AGENT_ID + "] (" + TEST_AGENT_NAME + ") " + TEST_AGENT_REGISTEREDIP_TXT
                     + "->" + TEST_ORIGINAL_ROUTE,
                 TEST_ORIGINAL_LOG},
        UseCase {"FormII",
                 TEST_QUEUE_ID,
                 std::string {} + "[" + TEST_AGENT_ID + "] (" + TEST_AGENT_NAME + ") " + TEST_IPV4 + "->"
                     + TEST_ORIGINAL_ROUTE,
                 TEST_ORIGINAL_LOG},
        UseCase {
            "FormIII",
            TEST_QUEUE_ID,
            std::string {} + "[" + TEST_AGENT_ID + "] (" + TEST_AGENT_NAME + ") " + TEST_EXTENDED_IPV6 + "->"
                + TEST_ORIGINAL_ROUTE,
            TEST_ORIGINAL_LOG,
            std::string {} + "[" + TEST_AGENT_ID + "] (" + TEST_AGENT_NAME + ") " + TEST_EXTENDED_IPV6_UNESCAPED + "->"
                + TEST_ORIGINAL_ROUTE,
        },
        UseCase {"FormIV", TEST_QUEUE_ID, TEST_IPV4, TEST_ORIGINAL_LOG},

        UseCase {"FormV", TEST_QUEUE_ID, TEST_EXTENDED_IPV6, TEST_ORIGINAL_LOG, TEST_EXTENDED_IPV6_UNESCAPED},

        UseCase {
            "FormVI",
            TEST_QUEUE_ID,
            std::string {} + "[" + TEST_AGENT_ID + "] (" + TEST_AGENT_NAME + ") " + TEST_AGENT_REGISTEREDIP_TXT + "->"
                + TEST_ESCAPED_COMMAND,
            TEST_ORIGINAL_LOG,
            std::string {} + "[" + TEST_AGENT_ID + "] (" + TEST_AGENT_NAME + ") " + TEST_AGENT_REGISTEREDIP_TXT + "->"
                + TEST_UNESCAPED_COMMAND,
        }

    };

    for (const auto& useCase : useCases)
    {
        execute(useCase);
    }
}

#include <string>

#include <gtest/gtest.h>

#include <parseEvent.hpp>

constexpr char TEST_QUEUE_ID {0x01};
constexpr char TEST_AGENT_ID[] {"404"};
constexpr char TEST_AGENT_NAME[] {"testAgentName"};
constexpr char TEST_AGENT_REGISTEREDIP_TXT[] {"testTxtIP"};
constexpr char TEST_ORIGINAL_ROUTE[] {"/test/Route"};
constexpr char TEST_IPV4[] {"1.205.0.44"};
constexpr char TEST_EXTENDED_IPV6[] {"ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B"};
constexpr char TEST_ORIGINAL_LOG[] {"Testing -> log : containing ([)] symbols."};

TEST(parseOssecEvent, InvalidEventFormat)
{
    const std::string event {"Invalid event format string"};
    ASSERT_THROW(base::parseEvent::parseOssecEvent(event), std::runtime_error);
}

TEST(parseOssecEvent, InvalidShortEvent)
{
    const std::string event {"x::"};
    ASSERT_THROW(base::parseEvent::parseOssecEvent(event), std::runtime_error);
}

TEST(parseOssecEvent, FormI)
{
    const std::string event {std::string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_AGENT_REGISTEREDIP_TXT + "->"
                        + TEST_ORIGINAL_ROUTE + ":" + TEST_ORIGINAL_LOG};

    auto e = base::parseEvent::parseOssecEvent(event);

    auto value = e->getInt(base::parseEvent::EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(base::parseEvent::EVENT_AGENT_ID);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_ID);

    valueStr = e->getString(base::parseEvent::EVENT_AGENT_NAME);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_NAME);

    valueStr = e->getString(base::parseEvent::EVENT_REGISTERED_IP);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_REGISTEREDIP_TXT);

    valueStr = e->getString(base::parseEvent::EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_ROUTE);

    valueStr = e->getString(base::parseEvent::EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(parseOssecEvent, FormII)
{
    const std::string event {std::string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_IPV4 + "->" + TEST_ORIGINAL_ROUTE
                        + ":" + TEST_ORIGINAL_LOG};

    auto e = base::parseEvent::parseOssecEvent(event);

    auto value = e->getInt(base::parseEvent::EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(base::parseEvent::EVENT_AGENT_ID);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_ID);

    valueStr = e->getString(base::parseEvent::EVENT_AGENT_NAME);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_NAME);

    valueStr = e->getString(base::parseEvent::EVENT_REGISTERED_IP);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_IPV4);

    valueStr = e->getString(base::parseEvent::EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_ROUTE);

    valueStr = e->getString(base::parseEvent::EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(parseOssecEvent, FormIII)
{
    const std::string event {std::string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_EXTENDED_IPV6 + "->"
                        + TEST_ORIGINAL_ROUTE + ":" + TEST_ORIGINAL_LOG};

    auto e = base::parseEvent::parseOssecEvent(event);

    auto value = e->getInt(base::parseEvent::EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(base::parseEvent::EVENT_AGENT_ID);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_ID);

    valueStr = e->getString(base::parseEvent::EVENT_AGENT_NAME);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_NAME);

    valueStr = e->getString(base::parseEvent::EVENT_REGISTERED_IP);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_EXTENDED_IPV6);

    valueStr = e->getString(base::parseEvent::EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_ROUTE);

    valueStr = e->getString(base::parseEvent::EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(parseOssecEvent, FormIV)
{
    const std::string event {std::string {} + TEST_QUEUE_ID + ":" + TEST_IPV4 + ":"
                        + TEST_ORIGINAL_LOG};

    auto e = base::parseEvent::parseOssecEvent(event);

    auto value = e->getInt(base::parseEvent::EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(base::parseEvent::EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_IPV4);

    valueStr = e->getString(base::parseEvent::EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(parseOssecEvent, FormV)
{
    const std::string event {std::string {} + TEST_QUEUE_ID + ":" + TEST_EXTENDED_IPV6 + ":"
                        + TEST_ORIGINAL_LOG};

    auto e = base::parseEvent::parseOssecEvent(event);

    auto value = e->getInt(base::parseEvent::EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(base::parseEvent::EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_EXTENDED_IPV6);

    valueStr = e->getString(base::parseEvent::EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

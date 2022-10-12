#include <server/protocolHandler.hpp>

#include <gtest/gtest.h>
#include <logging/logging.hpp>

using namespace engineserver;

using std::string;

constexpr char TEST_QUEUE_ID {0x01};
constexpr char TEST_AGENT_ID[] {"404"};
constexpr char TEST_AGENT_NAME[] {"testAgentName"};
constexpr char TEST_AGENT_REGISTEREDIP_TXT[] {"testTxtIP"};
constexpr char TEST_ORIGINAL_ROUTE[] {"/test/Route"};
constexpr char TEST_IPV4[] {"1.205.0.44"};
constexpr char TEST_EXTENDED_IPV6[] {"ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B"};
constexpr char TEST_ORIGINAL_LOG[] {"Testing -> log : containing ([)] symbols."};

TEST(protocolHandler, InvalidEventFormat)
{
    const string event {"Invalid event format string"};
    ASSERT_THROW(ProtocolHandler::parse(event), std::runtime_error);
}

TEST(protocolHandler, InvalidShortEvent)
{
    const string event {"x::"};
    ASSERT_THROW(ProtocolHandler::parse(event), std::runtime_error);
}

TEST(protocolHandler, FormI)
{
    const string event {string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_AGENT_REGISTEREDIP_TXT + "->"
                        + TEST_ORIGINAL_ROUTE + ":" + TEST_ORIGINAL_LOG};

    auto e = ProtocolHandler::parse(event);

    auto value = e->getInt(EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(EVENT_AGENT_ID);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_ID);

    valueStr = e->getString(EVENT_AGENT_NAME);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_NAME);

    valueStr = e->getString(EVENT_REGISTERED_IP);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_REGISTEREDIP_TXT);

    valueStr = e->getString(EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_ROUTE);

    valueStr = e->getString(EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormII)
{
    const string event {string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_IPV4 + "->" + TEST_ORIGINAL_ROUTE
                        + ":" + TEST_ORIGINAL_LOG};

    auto e = ProtocolHandler::parse(event);

    auto value = e->getInt(EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(EVENT_AGENT_ID);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_ID);

    valueStr = e->getString(EVENT_AGENT_NAME);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_NAME);

    valueStr = e->getString(EVENT_REGISTERED_IP);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_IPV4);

    valueStr = e->getString(EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_ROUTE);

    valueStr = e->getString(EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormIII)
{
    const string event {string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_EXTENDED_IPV6 + "->"
                        + TEST_ORIGINAL_ROUTE + ":" + TEST_ORIGINAL_LOG};

    auto e = ProtocolHandler::parse(event);

    auto value = e->getInt(EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(EVENT_AGENT_ID);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_ID);

    valueStr = e->getString(EVENT_AGENT_NAME);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_AGENT_NAME);

    valueStr = e->getString(EVENT_REGISTERED_IP);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_EXTENDED_IPV6);

    valueStr = e->getString(EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_ROUTE);

    valueStr = e->getString(EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormIV)
{
    const string event {string {} + TEST_QUEUE_ID + ":" + TEST_IPV4 + ":"
                        + TEST_ORIGINAL_LOG};

    auto e = ProtocolHandler::parse(event);

    auto value = e->getInt(EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_IPV4);

    valueStr = e->getString(EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormV)
{
    const string event {string {} + TEST_QUEUE_ID + ":" + TEST_EXTENDED_IPV6 + ":"
                        + TEST_ORIGINAL_LOG};

    auto e = ProtocolHandler::parse(event);

    auto value = e->getInt(EVENT_QUEUE_ID);
    ASSERT_EQ(value.value(), TEST_QUEUE_ID);

    auto valueStr = e->getString(EVENT_ORIGIN);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_EXTENDED_IPV6);

    valueStr = e->getString(EVENT_LOG);
    ASSERT_STREQ(valueStr.value().c_str(), TEST_ORIGINAL_LOG);
}

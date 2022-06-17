#include <protocolHandler.hpp>

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

    auto value = &e->getEvent()->get(EVENT_QUEUE_ID);
    ASSERT_EQ(value->GetInt(), TEST_QUEUE_ID);

    value = &e->getEvent()->get(EVENT_AGENT_ID);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_ID);

    value = &e->getEvent()->get(EVENT_AGENT_NAME);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_NAME);

    value = &e->getEvent()->get(EVENT_REGISTERED_IP);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_REGISTEREDIP_TXT);

    value = &e->getEvent()->get(EVENT_ROUTE);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_ROUTE);

    value = &e->getEvent()->get(EVENT_LOG);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormII)
{
    const string event {string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_IPV4 + "->" + TEST_ORIGINAL_ROUTE
                        + ":" + TEST_ORIGINAL_LOG};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get(EVENT_QUEUE_ID);
    ASSERT_EQ(value->GetInt(), TEST_QUEUE_ID);

    value = &e->getEvent()->get(EVENT_AGENT_ID);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_ID);

    value = &e->getEvent()->get(EVENT_AGENT_NAME);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_NAME);

    value = &e->getEvent()->get(EVENT_REGISTERED_IP);
    ASSERT_STREQ(value->GetString(), TEST_IPV4);

    value = &e->getEvent()->get(EVENT_ROUTE);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_ROUTE);

    value = &e->getEvent()->get(EVENT_LOG);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormIII)
{
    const string event {string {} + TEST_QUEUE_ID + ":[" + TEST_AGENT_ID + "] ("
                        + TEST_AGENT_NAME + ") " + TEST_EXTENDED_IPV6 + "->"
                        + TEST_ORIGINAL_ROUTE + ":" + TEST_ORIGINAL_LOG};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get(EVENT_QUEUE_ID);
    ASSERT_EQ(value->GetInt(), TEST_QUEUE_ID);

    value = &e->getEvent()->get(EVENT_AGENT_ID);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_ID);

    value = &e->getEvent()->get(EVENT_AGENT_NAME);
    ASSERT_STREQ(value->GetString(), TEST_AGENT_NAME);

    value = &e->getEvent()->get(EVENT_REGISTERED_IP);
    ASSERT_STREQ(value->GetString(), TEST_EXTENDED_IPV6);

    value = &e->getEvent()->get(EVENT_ROUTE);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_ROUTE);

    value = &e->getEvent()->get(EVENT_LOG);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormIV)
{
    const string event {string {} + TEST_QUEUE_ID + ":" + TEST_IPV4 + ":"
                        + TEST_ORIGINAL_LOG};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get(EVENT_QUEUE_ID);
    ASSERT_EQ(value->GetInt(), TEST_QUEUE_ID);

    value = &e->getEvent()->get(EVENT_ROUTE);
    ASSERT_STREQ(value->GetString(), TEST_IPV4);

    value = &e->getEvent()->get(EVENT_LOG);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_LOG);
}

TEST(protocolHandler, FormV)
{
    const string event {string {} + TEST_QUEUE_ID + ":" + TEST_EXTENDED_IPV6 + ":"
                        + TEST_ORIGINAL_LOG};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get(EVENT_QUEUE_ID);
    ASSERT_EQ(value->GetInt(), TEST_QUEUE_ID);

    value = &e->getEvent()->get(EVENT_ROUTE);
    ASSERT_STREQ(value->GetString(), TEST_EXTENDED_IPV6);

    value = &e->getEvent()->get(EVENT_LOG);
    ASSERT_STREQ(value->GetString(), TEST_ORIGINAL_LOG);
}

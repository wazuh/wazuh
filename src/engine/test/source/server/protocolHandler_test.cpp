#include <protocolHandler.hpp>

#include <gtest/gtest.h>
#include <logging/logging.hpp>

using namespace engineserver;

TEST(protocolHandler, FormI)
{
    std::string event {"1:[678] (SomeAgentName) some_i_pi->/some/Route:Some testing -> "
                       "random : log containing ([)] symbols."};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get("/original/queue");
    ASSERT_EQ(value->GetInt(), '1');

    value = &e->getEvent()->get("/agent/id");
    ASSERT_STREQ(value->GetString(), "678");

    value = &e->getEvent()->get("/agent/name");
    ASSERT_STREQ(value->GetString(), "SomeAgentName");

    value = &e->getEvent()->get("/agent/registeredIP");
    ASSERT_STREQ(value->GetString(), "some_i_pi");

    value = &e->getEvent()->get("/original/route");
    ASSERT_STREQ(value->GetString(), "/some/Route");

    value = &e->getEvent()->get("/original/message");
    ASSERT_STREQ(value->GetString(),
                 "Some testing -> random : log containing ([)] symbols.");
}

TEST(protocolHandler, FormII)
{
    std::string event {"a:[678] (SomeAgentName) 1.55.200.0->/some/Route:Some testing -> "
                       "random : log containing ([)] symbols."};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get("/original/queue");
    ASSERT_EQ(value->GetInt(), 'a');

    value = &e->getEvent()->get("/agent/id");
    ASSERT_STREQ(value->GetString(), "678");

    value = &e->getEvent()->get("/agent/name");
    ASSERT_STREQ(value->GetString(), "SomeAgentName");

    value = &e->getEvent()->get("/agent/registeredIP");
    ASSERT_STREQ(value->GetString(), "1.55.200.0");

    value = &e->getEvent()->get("/original/route");
    ASSERT_STREQ(value->GetString(), "/some/Route");

    value = &e->getEvent()->get("/original/message");
    ASSERT_STREQ(value->GetString(),
                 "Some testing -> random : log containing ([)] symbols.");
}

TEST(protocolHandler, FormIII)
{
    std::string event {"a:[678] (SomeAgentName) "
                       "ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B->/some/Route:Some "
                       "testing -> random : log containing ([)] symbols."};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get("/original/queue");
    ASSERT_EQ(value->GetInt(), 'a');

    value = &e->getEvent()->get("/agent/id");
    ASSERT_STREQ(value->GetString(), "678");

    value = &e->getEvent()->get("/agent/name");
    ASSERT_STREQ(value->GetString(), "SomeAgentName");

    value = &e->getEvent()->get("/agent/registeredIP");
    ASSERT_STREQ(value->GetString(), "ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B");

    value = &e->getEvent()->get("/original/route");
    ASSERT_STREQ(value->GetString(), "/some/Route");

    value = &e->getEvent()->get("/original/message");
    ASSERT_STREQ(value->GetString(),
                 "Some testing -> random : log containing ([)] symbols.");
}

TEST(protocolHandler, FormIV)
{
    std::string event {
        "a:1.255.0.44:Some testing -> random : log containing ([)] symbols."};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get("/original/queue");
    ASSERT_EQ(value->GetInt(), 'a');

    value = &e->getEvent()->get("/original/route");
    ASSERT_STREQ(value->GetString(), "1.255.0.44");

    value = &e->getEvent()->get("/original/message");
    ASSERT_STREQ(value->GetString(),
                 "Some testing -> random : log containing ([)] symbols.");
}

TEST(protocolHandler, FormV)
{
    std::string event {"a:ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B:Some testing -> random "
                       ": log containing ([)] symbols."};
    auto e = ProtocolHandler::parse(event);

    auto value = &e->getEvent()->get("/original/queue");
    ASSERT_EQ(value->GetInt(), 'a');

    value = &e->getEvent()->get("/original/route");
    ASSERT_STREQ(value->GetString(), "ABCD:EFG0:1234:5678:0009:00AB:00C6:0D7B");

    value = &e->getEvent()->get("/original/message");
    ASSERT_STREQ(value->GetString(),
                 "Some testing -> random : log containing ([)] symbols.");
}

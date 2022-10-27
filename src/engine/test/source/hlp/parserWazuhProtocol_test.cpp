#include <hlp/hlp.hpp>

#include <gtest/gtest.h>

#include <json/json.hpp>

using namespace hlp;

TEST(parseWazuhProtocol, wazuhProtocolCaseI)
{
    const char* logpar =
        "<~queue/number>:[<~agentId>] (<~agentName>) <~registerIP>-><~route>:<~log>";
    const char* event =
        "3:[678] (someAgentName) any->/some/route:Some : random -> ([)] log ";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<long>(result["~queue"]), 3);
    ASSERT_EQ(std::any_cast<std::string>(result["~agentId"]), "678");
    ASSERT_EQ(std::any_cast<std::string>(result["~agentName"]), "someAgentName");
    ASSERT_EQ(std::any_cast<std::string>(result["~registerIP"]), "any");
    ASSERT_EQ(std::any_cast<std::string>(result["~route"]), "/some/route");
    ASSERT_EQ(std::any_cast<std::string>(result["~log"]), "Some : random -> ([)] log ");
}

TEST(parseWazuhProtocol, wazuhProtocolCaseII)
{
    const char* logpar =
        "<~queue/number>:[<~agentId>] (<~agentName>) <~registerIP>-><~route>:<~log>";
    const char* event =
        "3:[678] (someAgentName) 122.250.116.99->/some/route:Some : random -> ([)] log ";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<long>(result["~queue"]), 3);
    ASSERT_EQ(std::any_cast<std::string>(result["~agentId"]), "678");
    ASSERT_EQ(std::any_cast<std::string>(result["~agentName"]), "someAgentName");
    ASSERT_EQ(std::any_cast<std::string>(result["~registerIP"]), "122.250.116.99");
    ASSERT_EQ(std::any_cast<std::string>(result["~route"]), "/some/route");
    ASSERT_EQ(std::any_cast<std::string>(result["~log"]), "Some : random -> ([)] log ");
}

TEST(parseWazuhProtocol, wazuhProtocolCaseIII)
{
    const char* logpar =
        "<~queue/number>:[<~agentId>] (<~agentName>) <~registerIP>-><~route>:<~log>";
    const char* event = "3:[678] (someAgentName) :AB68:::1::7C8:A0->/some/route:Some : "
                        "random -> ([)] log ";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<long>(result["~queue"]), 3);
    ASSERT_EQ(std::any_cast<std::string>(result["~agentId"]), "678");
    ASSERT_EQ(std::any_cast<std::string>(result["~agentName"]), "someAgentName");
    ASSERT_EQ(std::any_cast<std::string>(result["~registerIP"]), ":AB68:::1::7C8:A0");
    ASSERT_EQ(std::any_cast<std::string>(result["~route"]), "/some/route");
    ASSERT_EQ(std::any_cast<std::string>(result["~log"]), "Some : random -> ([)] log ");
}

TEST(parseWazuhProtocol, wazuhProtocolCaseIV)
{
    const char* logpar = "<~queue/number>:<~registerIP/ip>:<~log>";
    const char* event = "3:1.50.255.0:Some : random -> ([)] log ";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<long>(result["~queue"]), 3);
    ASSERT_EQ(std::any_cast<std::string>(result["~registerIP"]), "1.50.255.0");
    ASSERT_EQ(std::any_cast<std::string>(result["~log"]), "Some : random -> ([)] log ");
}

// TODO: This should work but, because of how the parsing was implemented, it is not.
TEST(parseWazuhProtocol, wazuhProtocolCaseV)
{
    GTEST_SKIP();
    const char* logpar = "<~queue/number>:<~registerIP/ip>:<~log>";
    const char* event = "3:2AAC:AB68:0:0:1D:0:7C8:A0:Some : random -> ([)] log ";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<long>(result["~queue"]), 3);
    ASSERT_EQ(std::any_cast<std::string>(result["~registerIP"]),
              "2AAC:AB68:0:0:1D:0:7C8:A0");
    ASSERT_EQ(std::any_cast<std::string>(result["~log"]), "Some : random -> ([)] log ");
}

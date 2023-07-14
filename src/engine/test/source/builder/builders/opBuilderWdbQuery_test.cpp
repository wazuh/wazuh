#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>

#include <testsCommon.hpp>
#include <wdb/mockWdbHandler.hpp>
#include <wdb/mockWdbManager.hpp>

#include "opBuilderWdb.hpp"

using namespace base;
using namespace wazuhdb;
using namespace wazuhdb::mocks;
namespace bld = builder::internals::builders;

class opBuilderWdbQuery : public ::testing::Test
{

protected:
    std::shared_ptr<MockWdbManager> wdbManager;
    std::shared_ptr<MockWdbHandler> wdbHandler;

    void SetUp() override
    {
        initLogging();

        wdbManager = std::make_shared<MockWdbManager>();
        wdbHandler = std::make_shared<MockWdbHandler>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdbHandler));
    }

    void TearDown() override {}
};

// Build ok
TEST_F(opBuilderWdbQuery, BuildSimplest)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"agent 007 syscheck integrity_clear ...."},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderWdbQuery(wdbManager), tuple));
}

// TODO: the / of the path inside the json should be escaped!
TEST_F(opBuilderWdbQuery, BuildsWithJson)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {"agent 007 syscheck integrity_clear {\"tail\": \"tail\", "
                                  "\"checksum\":\"checksum\", \"begin\": \"/a/path\", \"end\": \"/z/path\"}"},
        std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderWdbQuery(wdbManager), tuple));
}

TEST_F(opBuilderWdbQuery, BuildsWithQueryRef)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderWdbQuery(wdbManager), tuple));
}

TEST_F(opBuilderWdbQuery, checkWrongQttyParams)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameter", "more params"},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(bld::getBuilderWdbQuery(wdbManager), tuple), std::runtime_error);
}

TEST_F(opBuilderWdbQuery, checkNoParams)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(bld::getBuilderWdbQuery(wdbManager), tuple), std::runtime_error);
}

TEST_F(opBuilderWdbQuery, gettingEmptyReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbQuery(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": ""}
    })")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/wdb/result"));
}

TEST_F(opBuilderWdbQuery, gettingNonExistingReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbQuery(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "not_query_parameters_": "query"}
    })")};

    result::Result<Event> result1 {op(event1)};

    ASSERT_FALSE(result1);
}

TEST_F(opBuilderWdbQuery, completeFunctioningWithtDBresponseNotOk)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbQuery(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    // TODO Should be null or inexistant??
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));
}

TEST_F(opBuilderWdbQuery, completeFunctioningWithtDBresponseWithPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbQuery(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(okQueryRes("payload")));

    result::Result<Event> result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_TRUE(result.payload().get()->isString("/wdb/result"));
    ASSERT_EQ(result.payload().get()->getString("/wdb/result"), "payload");
}

TEST_F(opBuilderWdbQuery, QueryResultCodeOkPayloadEmpty)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbQuery(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_TRUE(result.payload().get()->isString("/wdb/result"));
    ASSERT_EQ(result.payload().get()->getString("/wdb/result"), "");
}

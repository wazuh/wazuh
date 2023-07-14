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

class opBuilderWdbUpdate : public ::testing::Test
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
TEST_F(opBuilderWdbUpdate, Build)
{
    auto tuple {std::make_tuple(std::string {"/sourceField"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"agent 007 syscheck integrity_clear ...."},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple));
}

TEST_F(opBuilderWdbUpdate, BuildsWithJson)
{

    auto tuple {std::make_tuple(
        std::string {"/sourceField"},
        std::string {"wdb_update"},
        std::vector<std::string> {"agent 007 syscheck integrity_clear {\"tail\": \"tail\", "
                                  "\"checksum\":\"checksum\", \"begin\": \"/a/path\", \"end\": \"/z/path\"}"},
        std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple));
}

TEST_F(opBuilderWdbUpdate, BuildsWithQueryRef)
{

    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple));
}

TEST_F(opBuilderWdbUpdate, checkWrongQttyParams)
{

    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters", "param2"},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple), std::runtime_error);
}

TEST_F(opBuilderWdbUpdate, gettingEmptyReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": ""}
    })")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
}

TEST_F(opBuilderWdbUpdate, gettingNonExistingReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "not_query_parameters": "something"}
    })")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
}

TEST_F(opBuilderWdbUpdate, completeFunctioningWithBadResponse)
{

    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    result::Result<Event> result1 {op(event1)};

    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload()->isBool("/wdb/result"));
    ASSERT_FALSE(result1.payload()->getBool("/wdb/result").value());
}

TEST_F(opBuilderWdbUpdate, completeFunctioningWithOkResponse)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result1 {op(event1)};

    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload()->isBool("/wdb/result"));
    ASSERT_TRUE(result1.payload()->getBool("/wdb/result").value());
}

TEST_F(opBuilderWdbUpdate, completeFunctioningWithOkResponseWPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(okQueryRes("with discarded payload")));

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload()->isBool("/wdb/result"));
    ASSERT_TRUE(result1.payload()->getBool("/wdb/result").value());
}

TEST_F(opBuilderWdbUpdate, QueryResultCodeNotOkWithPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_update"},
                                std::vector<std::string> {"$wdb.query_parameters"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*wdbManager, connection());

    auto op {std::apply(bld::getBuilderWdbUpdate(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(testing::StrEq("agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": "
                                              "\"checksum\", \"begin\": \"path\", \"end\": \"path\"}"),
                               testing::_))
        .WillOnce(testing::Return(errorQueryRes("Random payload")));

    result::Result<Event> result1 {op(event1)};

    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload()->isBool("/wdb/result"));
    ASSERT_FALSE(result1.payload()->getBool("/wdb/result").value());
}

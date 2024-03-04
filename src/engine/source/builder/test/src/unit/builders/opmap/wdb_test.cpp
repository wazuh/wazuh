#include "builders/baseBuilders_test.hpp"
#include "builders/opmap/wdb.hpp"

#include <wdb/mockWdbHandler.hpp>
#include <wdb/mockWdbManager.hpp>

using namespace wazuhdb::mocks;
using namespace builder::builders::opmap;

namespace
{
template<typename Builder>
auto getBuilder(Builder&& builder)
{
    return [=]()
    {
        auto mockWdbManager = std::make_shared<MockWdbManager>();
        return builder(mockWdbManager);
    };
}

template<typename Builder>
auto getBuilderExpectHandler(Builder&& builder)
{
    return [=]()
    {
        auto mockWdbManager = std::make_shared<MockWdbManager>();
        auto mockWdbHandler = std::make_shared<MockWdbHandler>();

        EXPECT_CALL(*mockWdbManager, connection()).WillOnce(testing::Return(mockWdbHandler));
        return builder(mockWdbManager);
    };
}

template<typename Builder, typename Behaviour>
auto getBuilderExpectHandler(Builder&& builder, Behaviour&& behaviour)
{
    return [=]()
    {
        auto mockWdbManager = std::make_shared<MockWdbManager>();
        auto mockWdbHandler = std::make_shared<MockWdbHandler>();

        EXPECT_CALL(*mockWdbManager, connection()).WillOnce(testing::Return(mockWdbHandler));
        behaviour(mockWdbHandler);
        return builder(mockWdbManager);
    };
}

auto expectCustomRef(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectCustomRef(const std::string& ref, json::Json value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return value;
    };
}

auto expectJTypeRef(const std::string& ref, json::Json::Type jType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(ref))).WillOnce(testing::Return(jType));

        return None {};
    };
}

auto expectOkQuery(const std::string& query, const std::string& message = "")
{
    return [=](const std::shared_ptr<MockWdbHandler>& mockWdbHandler)
    {
        if (message.empty())
        {
            EXPECT_CALL(*mockWdbHandler, tryQueryAndParseResult(query, wazuhdb::DEFAULT_TRY_ATTEMPTS))
                .WillOnce(testing::Return(okQueryRes()));
        }
        else
        {
            EXPECT_CALL(*mockWdbHandler, tryQueryAndParseResult(query, wazuhdb::DEFAULT_TRY_ATTEMPTS))
                .WillOnce(testing::Return(okQueryRes(message)));
        }
    };
}

auto expectNotOkQuery(const std::string& query)
{
    return [=](const std::shared_ptr<MockWdbHandler>& mockWdbHandler)
    {
        EXPECT_CALL(*mockWdbHandler, tryQueryAndParseResult(query, wazuhdb::DEFAULT_TRY_ATTEMPTS))
            .WillOnce(testing::Return(errorQueryRes()));
    };
}

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderWithDepsTest,
    testing::Values(
        /*** Query ***/
        MapDepsT({}, getBuilder(getWdbQueryBuilder), FAILURE()),
        MapDepsT({makeValue(R"("query")")}, getBuilderExpectHandler(getWdbQueryBuilder), SUCCESS()),
        MapDepsT({makeValue(R"("query")"), makeValue(R"("other")")}, getBuilder(getWdbQueryBuilder), FAILURE()),
        MapDepsT({makeValue(R"("")")}, getBuilder(getWdbQueryBuilder), FAILURE()),
        MapDepsT({makeValue(R"(1)")}, getBuilder(getWdbQueryBuilder), FAILURE()),
        MapDepsT({makeRef("ref")}, getBuilderExpectHandler(getWdbQueryBuilder), SUCCESS(expectCustomRef("ref"))),
        MapDepsT({makeRef("ref"), makeValue(R"("other")")}, getBuilder(getWdbQueryBuilder), FAILURE()),
        MapDepsT({makeRef("ref")},
                 getBuilderExpectHandler(getWdbQueryBuilder),
                 SUCCESS(expectJTypeRef("ref", json::Json::Type::String))),
        MapDepsT({makeRef("ref")},
                 getBuilder(getWdbQueryBuilder),
                 FAILURE(expectJTypeRef("ref", json::Json::Type::Number))),
        /*** Update ***/
        MapDepsT({}, getBuilder(getWdbUpdateBuilder), FAILURE()),
        MapDepsT({makeValue(R"("query")")}, getBuilderExpectHandler(getWdbUpdateBuilder), SUCCESS()),
        MapDepsT({makeValue(R"("query")"), makeValue(R"("other")")}, getBuilder(getWdbUpdateBuilder), FAILURE()),
        MapDepsT({makeValue(R"("")")}, getBuilder(getWdbUpdateBuilder), FAILURE()),
        MapDepsT({makeValue(R"(1)")}, getBuilder(getWdbUpdateBuilder), FAILURE()),
        MapDepsT({makeRef("ref")}, getBuilderExpectHandler(getWdbUpdateBuilder), SUCCESS(expectCustomRef("ref"))),
        MapDepsT({makeRef("ref"), makeValue(R"("other")")}, getBuilder(getWdbUpdateBuilder), FAILURE()),
        MapDepsT({makeRef("ref")},
                 getBuilderExpectHandler(getWdbUpdateBuilder),
                 SUCCESS(expectJTypeRef("ref", json::Json::Type::String))),
        MapDepsT({makeRef("ref")},
                 getBuilder(getWdbUpdateBuilder),
                 FAILURE(expectJTypeRef("ref", json::Json::Type::Number)))),
    testNameFormatter<MapBuilderWithDepsTest>("WDB"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapOperationWithDepsTest,
                         testing::Values(
                             /*** Query ***/
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbQueryBuilder, expectOkQuery("query")),
                                      {makeValue(R"("query")")},
                                      SUCCESS(json::Json {R"("")"})),
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbQueryBuilder, expectOkQuery("query", "message")),
                                      {makeValue(R"("query")")},
                                      SUCCESS(json::Json {R"("message")"})),
                             MapDepsT(R"({"ref": "query"})",
                                      getBuilderExpectHandler(getWdbQueryBuilder, expectOkQuery("query")),
                                      {makeRef("ref")},
                                      SUCCESS(expectCustomRef("ref", json::Json {R"("")"}))),
                             MapDepsT(R"({"ref": "query"})",
                                      getBuilderExpectHandler(getWdbQueryBuilder, expectOkQuery("query", "message")),
                                      {makeRef("ref")},
                                      SUCCESS(expectCustomRef("ref", json::Json {R"("message")"}))),
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbQueryBuilder),
                                      {makeRef("ref")},
                                      FAILURE(expectCustomRef("ref"))),
                             MapDepsT(R"({"ref": 1})",
                                      getBuilderExpectHandler(getWdbQueryBuilder),
                                      {makeRef("ref")},
                                      FAILURE(expectCustomRef("ref"))),
                             MapDepsT(R"({"ref": ""})",
                                      getBuilderExpectHandler(getWdbQueryBuilder),
                                      {makeRef("ref")},
                                      FAILURE(expectCustomRef("ref"))),
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbQueryBuilder, expectNotOkQuery("query")),
                                      {makeValue(R"("query")")},
                                      FAILURE()),
                             /*** Update ***/
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder, expectOkQuery("query")),
                                      {makeValue(R"("query")")},
                                      SUCCESS(json::Json {R"(true)"})),
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder, expectOkQuery("query", "message")),
                                      {makeValue(R"("query")")},
                                      SUCCESS(json::Json {R"(true)"})),
                             MapDepsT(R"({"ref": "query"})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder, expectOkQuery("query")),
                                      {makeRef("ref")},
                                      SUCCESS(expectCustomRef("ref", json::Json {R"(true)"}))),
                             MapDepsT(R"({"ref": "query"})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder, expectOkQuery("query", "message")),
                                      {makeRef("ref")},
                                      SUCCESS(expectCustomRef("ref", json::Json {R"(true)"}))),
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder),
                                      {makeRef("ref")},
                                      FAILURE(expectCustomRef("ref"))),
                             MapDepsT(R"({"ref": 1})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder),
                                      {makeRef("ref")},
                                      FAILURE(expectCustomRef("ref"))),
                             MapDepsT(R"({"ref": ""})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder),
                                      {makeRef("ref")},
                                      FAILURE(expectCustomRef("ref"))),
                             MapDepsT(R"({})",
                                      getBuilderExpectHandler(getWdbUpdateBuilder, expectNotOkQuery("query")),
                                      {makeValue(R"("query")")},
                                      FAILURE())),
                         testNameFormatter<MapOperationWithDepsTest>("WDB"));
}

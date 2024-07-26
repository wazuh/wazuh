#include "builders/baseBuilders_test.hpp"
#include "builders/optransform/windows.hpp"

#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/mockKvdbManager.hpp>

using namespace builder::builders;
using namespace kvdb::mocks;

namespace
{
constexpr auto SCOPE = "test";

auto getBuilder()
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockKVDBManager>();
        return getWindowsSidListDescHelperBuilder(kvdbManager, SCOPE);
    };
}

auto getBuilderExpectHandler(const std::string& kvdbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockKVDBManager>();
        auto kvdbHandler = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbManager, getKVDBHandler(kvdbName, SCOPE)).WillOnce(testing::Return(kvdbHandler));
        return getWindowsSidListDescHelperBuilder(kvdbManager, SCOPE);
    };
}

template<typename Behaviour>
auto getBuilderExpectHandler(const std::string& kvdbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockKVDBManager>();
        auto kvdbHandler = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbManager, getKVDBHandler(kvdbName, SCOPE)).WillOnce(testing::Return(kvdbHandler));
        behaviour(kvdbHandler);
        return getWindowsSidListDescHelperBuilder(kvdbManager, SCOPE);
    };
}

auto getBuilderExpectHandlerError(const std::string& kvdbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockKVDBManager>();
        EXPECT_CALL(*kvdbManager, getKVDBHandler(kvdbName, SCOPE))
            .WillOnce(testing::Return(kvdbGetKVDBHandlerError("error")));
        return getWindowsSidListDescHelperBuilder(kvdbManager, SCOPE);
    };
}

auto customRefExpected(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));

        return None {};
    };
}

auto customRefExpected(const std::string& ref, base::Event result)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));

        return result;
    };
}

auto jTypeRefExpected(const std::string& ref, json::Json::Type jType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(ref))).WillOnce(testing::Return(jType));

        return None {};
    };
}

auto expectKvdbGet(const std::string& key, const std::string& value)
{
    json::Json jsonValue(value.c_str());
    return [=](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
    {
        EXPECT_CALL(*kvdbHandler, get(key)).WillOnce(testing::Return(value));
    };
}

auto expectKvdbGetError(const std::string& key)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
    {
        EXPECT_CALL(*kvdbHandler, get(key)).WillOnce(testing::Return(kvdbGetError("error")));
    };
}

} // namespace

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderWithDepsTest,
    testing::Values(
        TransformDepsT({}, getBuilder(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getBuilder(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")}, getBuilder(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("value")")}, getBuilder(), FAILURE()),
        TransformDepsT({makeRef("ref"), makeRef("ref")}, getBuilder(), FAILURE()),
        TransformDepsT({makeRef("ref"), makeValue(R"("value")")}, getBuilder(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandlerError("dbname"),
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname", expectKvdbGetError(detail::ACC_SID_DESC_KEY)),
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname", expectKvdbGet(detail::ACC_SID_DESC_KEY, R"("notObject")")),
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname", expectKvdbGet(detail::ACC_SID_DESC_KEY, R"({"key": 1})")),
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname", expectKvdbGet(detail::ACC_SID_DESC_KEY, R"({})")),
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGetError(detail::DOM_SPC_SID_KEY)(kvdbHandler);
                                               }),
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGet(detail::DOM_SPC_SID_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                               }),
                       SUCCESS(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGet(detail::DOM_SPC_SID_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                               }),
                       SUCCESS(jTypeRefExpected("ref", json::Json::Type::String)))),
    testNameFormatter<TransformBuilderWithDepsTest>("Win"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationWithDepsTest,
    testing::Values(
        TransformDepsT(R"({"ref": "%{key}"})",
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGet(detail::DOM_SPC_SID_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                               }),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       SUCCESS(customRefExpected("ref", makeEvent(R"({"ref":"%{key}","target":["value"]})")))),
        TransformDepsT(R"({})",
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGet(detail::DOM_SPC_SID_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                               }),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT(R"({"ref": 1})",
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGet(detail::DOM_SPC_SID_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                               }),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref"))),
        // TODO event -> {"ref": "invalid format"} should be checked on the helper, as of now this will succeed
        TransformDepsT(R"({"ref": ""})",
                       getBuilderExpectHandler("dbname",
                                               [](const std::shared_ptr<MockKVDBHandler>& kvdbHandler)
                                               {
                                                   expectKvdbGet(detail::ACC_SID_DESC_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                                   expectKvdbGet(detail::DOM_SPC_SID_KEY,
                                                                 R"({"key": "value"})")(kvdbHandler);
                                               }),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref")))
        // TODO -> {"ref": "desc"} outputs in "ref": ["s"]
        ),
    testNameFormatter<TransformOperationWithDepsTest>("Win"));
} // namespace transformoperatestest

#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/kvdb.hpp"
#include <kvdb/mockKvdbManager.hpp>

using namespace kvdb::mocks;

namespace
{
auto kvdbMock = std::make_shared<MockKVDBManager>();
auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
constexpr auto SCOPE = "test_scope";

auto expectKvdb(const std::string& name)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        return None {};
    };
}

auto expectKvdbError()
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbMock, getKVDBHandler(testing::_, SCOPE)).WillOnce(testing::Return(base::Error {"error"}));
        return None {};
    };
}

auto expectKvdbContainsKey(const std::string& name, const std::string& key, bool contains = true)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        EXPECT_CALL(*kvdbHandlerMock, contains(key)).WillOnce(testing::Return(contains));
        return None {};
    };
}

auto expectKvdbContainsError(const std::string& name)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        EXPECT_CALL(*kvdbHandlerMock, contains(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
        return None {};
    };
}

auto customRefExpected(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath(ref))).WillOnce(testing::Return(false));

        return None {};
    };
}

auto jTypeRefExpected(const std::string& ref, json::Json::Type jType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        auto sType = schemf::Type::BINARY;
        EXPECT_CALL(*mocks.schema, getType(DotPath(ref))).WillOnce(testing::Return(sType));
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, getJsonType(sType)).WillOnce(testing::Return(jType));

        return None {};
    };
}

auto expectKvdbGetValue(const std::string& name, const std::string& key, const std::string& value, base::Event event)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        EXPECT_CALL(*kvdbHandlerMock, get(key)).WillOnce(testing::Return(value));
        return event;
    };
}

auto expectKvdbGetError(const std::string& name, const std::string& key)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        EXPECT_CALL(*kvdbHandlerMock, get(key)).WillOnce(testing::Return(base::Error {"error"}));
        return None {};
    };
}
} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        /*** MATCH ***/
        FilterT({}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeRef("ref")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"("name")")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), SUCCESS(expectKvdb("name"))),
        FilterT({makeValue(R"("name")"), makeValue(R"("value")")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(1)")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(1.1)")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(true)")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(null)")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"([])")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"({})")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"("name")")}, getOpBuilderKVDBMatch(kvdbMock, SCOPE), FAILURE(expectKvdbError())),
        FilterT({makeValue(R"("name")")}, getOpBuilderKVDBMatch(nullptr, SCOPE), FAILURE()),
        /*** NOT MATCH ***/
        FilterT({}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeRef("ref")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"("name")")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), SUCCESS(expectKvdb("name"))),
        FilterT({makeValue(R"("name")"), makeValue(R"("value")")},
                getOpBuilderKVDBNotMatch(kvdbMock, SCOPE),
                FAILURE()),
        FilterT({makeValue(R"(1)")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(1.1)")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(true)")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"(null)")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"([])")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"({})")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE()),
        FilterT({makeValue(R"("name")")}, getOpBuilderKVDBNotMatch(kvdbMock, SCOPE), FAILURE(expectKvdbError())),
        FilterT({makeValue(R"("name")")}, getOpBuilderKVDBNotMatch(nullptr, SCOPE), FAILURE())),
    testNameFormatter<FilterBuilderTest>("KVDB"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterOperationTest,
                         testing::Values(
                             /*** MATCH ***/
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     SUCCESS(expectKvdbContainsKey("dbname", "key"))),
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBMatch(kvdbMock, SCOPE),
                                     "notTarget",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdb("dbname"))),
                             FilterT(R"({"target": 1})",
                                     getOpBuilderKVDBMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdb("dbname"))),
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdbContainsError("dbname"))),
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdbContainsKey("dbname", "key", false))),
                             /*** NOT MATCH ***/
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBNotMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     SUCCESS(expectKvdbContainsKey("dbname", "key", false))),
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBNotMatch(kvdbMock, SCOPE),
                                     "notTarget",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdb("dbname"))),
                             FilterT(R"({"target": 1})",
                                     getOpBuilderKVDBNotMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdb("dbname"))),
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBNotMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdbContainsError("dbname"))),
                             FilterT(R"({"target": "key"})",
                                     getOpBuilderKVDBNotMatch(kvdbMock, SCOPE),
                                     "target",
                                     {makeValue(R"("dbname")")},
                                     FAILURE(expectKvdbContainsKey("dbname", "key")))

                                 ),
                         testNameFormatter<FilterOperationTest>("KVDB"));
} // namespace filteroperatestest

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderTest,
    testing::Values(
        /*** GET ***/
        TransformT({}, getOpBuilderKVDBGet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")")}, getOpBuilderKVDBGet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   SUCCESS(expectKvdb("dbname"))),
        TransformT({makeRef("ref"), makeValue(R"("key")")}, getOpBuilderKVDBGet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(1)")}, getOpBuilderKVDBGet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   FAILURE(expectKvdbError()))

            ),
    testNameFormatter<TransformBuilderTest>("KVDB"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(
        /*** GET ***/
        TransformT(R"({})",
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")")},
                   SUCCESS(expectKvdbGetValue("dbname", "key", R"("value")", makeEvent(R"({"target": "value"})")))),
        TransformT(R"({"ref": "key"})",
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdbGetValue("dbname", "key", R"("value")", nullptr)(mocks);
                           return makeEvent(R"({"ref": "key", "target": "value"})");
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({"ref": 1})",
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({"ref": "key"})",
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdbGetError("dbname", "key")(mocks);
                           return None {};
                       })),
        TransformT(R"({"ref": "key"})",
                   getOpBuilderKVDBGet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdbGetValue("dbname", "key", "malformedJsonValue", nullptr)(mocks);
                           return None {};
                       }))

            ),
    testNameFormatter<TransformOperationTest>("KVDB"));
} // namespace transformoperatestest

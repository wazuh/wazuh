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

template<typename... T>
auto customRefExpected(T... refs)
{
    return [=](const BuildersMocks& mocks)
    {
        if (sizeof...(refs) > 0)
        {
            EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        }
        else
        {
            EXPECT_CALL(*mocks.ctx, schema());
        }

        for (const auto& ref : {refs...})
        {
            EXPECT_CALL(*mocks.schema, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        }

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

auto expectKvdbSet(const std::string& key, const std::string& jValue)
{
    json::Json value {jValue.c_str()};
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbHandlerMock, set(key, value)).WillOnce(testing::Return(base::noError()));
        return None {};
    };
}

auto expectKvdbSetError(const std::string& key, const std::string& jValue)
{
    json::Json value {jValue.c_str()};
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbHandlerMock, set(key, value)).WillOnce(testing::Return(base::Error {"error"}));
        return None {};
    };
}

auto expectKvdbDelete(const std::string& key)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbHandlerMock, remove(key)).WillOnce(testing::Return(base::noError()));
        return None {};
    };
}

auto expectKvdbDeleteError(const std::string& key)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*kvdbHandlerMock, remove(key)).WillOnce(testing::Return(base::Error {"error"}));
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
                   FAILURE(expectKvdbError())),
        /*** GET MERGE ***/
        TransformT({}, getOpBuilderKVDBGetMerge(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")")}, getOpBuilderKVDBGetMerge(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   SUCCESS(expectKvdb("dbname"))),
        TransformT({makeRef("ref"), makeValue(R"("key")")}, getOpBuilderKVDBGetMerge(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(1)")}, getOpBuilderKVDBGetMerge(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   FAILURE(expectKvdbError())),
        /*** SET ***/
        TransformT({}, getOpBuilderKVDBSet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")")}, getOpBuilderKVDBSet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")}, getOpBuilderKVDBSet(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   SUCCESS(expectKvdb("dbname"))),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")"), makeValue(R"("other")")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"(1)")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   SUCCESS(expectKvdb("dbname"))),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(1)"), makeValue(R"("value")")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"(1)"), makeValue(R"("key")"), makeValue(R"("value")")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("keyRef")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           jTypeRefExpected("keyRef", json::Json::Type::String)(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   FAILURE(jTypeRefExpected("keyRef", json::Json::Type::Number))),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   FAILURE(expectKvdbError())),
        /*** DELETE ***/
        TransformT({}, getOpBuilderKVDBDelete(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")")}, getOpBuilderKVDBDelete(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   SUCCESS(expectKvdb("dbname"))),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"(1)"), makeValue(R"("key")")}, getOpBuilderKVDBDelete(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(1)")}, getOpBuilderKVDBDelete(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   FAILURE(expectKvdbError())),
        /*** GET ARRAY ***/
        TransformT({}, getOpBuilderKVDBGetArray(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")")}, getOpBuilderKVDBGetArray(kvdbMock, SCOPE), FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   SUCCESS(expectKvdb("dbname"))),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"(1)"), makeValue(R"(["k0", "k1"])")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])"), makeValue(R"("other")")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeValue(R"("not an array")")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   FAILURE()),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                           EXPECT_CALL(*mocks.schema, isArray(DotPath("ref"))).WillOnce(testing::Return(true));
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.schema, isArray(DotPath("ref"))).WillOnce(testing::Return(true));
                           jTypeRefExpected("ref", json::Json::Type::Number)(mocks);
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeRef("ref")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
                           EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.schema, isArray(DotPath("ref"))).WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   FAILURE(expectKvdbError()))
        /*** BITMASK TO TABLE ***/

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
                       })),
        /*** GET MERGE ***/
        TransformT(R"({"target": [0, 2]})",
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")")},
                   SUCCESS(expectKvdbGetValue("dbname", "key", R"([1, 3])", makeEvent(R"({"target": [0, 2, 1, 3]})")))),
        TransformT(R"({"target": {"a": 0, "b": 2}, "ref": "key"})",
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdbGetValue("dbname", "key", R"({"b": 3, "c": 4})", nullptr)(mocks);
                           return makeEvent(R"({"target": {"a": 0, "b": 3, "c": 4}, "ref": "key"})");
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdbGetValue("dbname", "key", R"([1, 3])", nullptr)(mocks);
                           return None {};
                       })),
        TransformT(R"({"target": []})",
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdbGetValue("dbname", "key", R"({"a": 0})", nullptr)(mocks);
                           return None {};
                       })),
        TransformT(R"({"target": "value"})",
                   getOpBuilderKVDBGetMerge(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdbGetValue("dbname", "key", R"("othervalue")", nullptr)(mocks);
                           return None {};
                       })),
        /*** SET ***/
        TransformT(R"({})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbSet("key", R"("value")")(mocks);
                           return makeEvent(R"({"target": true})");
                       })),
        TransformT(R"({"ref": "key"})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           expectKvdbSet("key", R"("value")")(mocks);
                           return makeEvent(R"({"ref": "key", "target": true})");
                       })),
        TransformT(R"({"ref": "value"})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbSet("key", R"("value")")(mocks);
                           return makeEvent(R"({"ref": "value", "target": true})");
                       })),
        TransformT(R"({"keyRef": "key", "valueRef": "value"})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("keyRef")(mocks);
                           expectKvdb("dbname")(mocks);
                           expectKvdbSet("key", R"("value")")(mocks);
                           return makeEvent(R"({"keyRef": "key", "valueRef": "value", "target": true})");
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("keyRef"), makeValue(R"("value")")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("keyRef")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({"ref": 1})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                   FAILURE(expectKvdb("dbname"))),
        TransformT(R"({"ref": "value"})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbSetError("key", R"("value")")(mocks);
                           return None {};
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBSet(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbSetError("key", R"("value")")(mocks);
                           return None {};
                       })),
        /*** DELETE ***/
        TransformT(R"({})",
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"("key")")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbDelete("key")(mocks);
                           return makeEvent(R"({"target": true})");
                       })),
        TransformT(R"({"ref": "key"})",
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           expectKvdbDelete("key")(mocks);
                           return makeEvent(R"({"ref": "key", "target": true})");
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
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
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
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
                   getOpBuilderKVDBDelete(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           expectKvdbDeleteError("key")(mocks);
                           return None {};
                       })),
        /*** GET ARRAY ***/
        TransformT(R"({})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdbGetValue("dbname", "k0", R"("v0")", nullptr)(mocks);
                           expectKvdbGetValue("dbname", "k1", R"("v1")", nullptr)(mocks);
                           return makeEvent(R"({"target": ["v0", "v1"]})");
                       })),
        TransformT(R"({"target": ["v2"]})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdbGetValue("dbname", "k0", R"("v0")", nullptr)(mocks);
                           expectKvdbGetValue("dbname", "k1", R"("v1")", nullptr)(mocks);
                           return makeEvent(R"({"target": ["v2", "v0", "v1"]})");
                       })),
        TransformT(R"({"ref": ["k0", "k1"]})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdbGetValue("dbname", "k0", R"("v0")", nullptr)(mocks);
                           expectKvdbGetValue("dbname", "k1", R"("v1")", nullptr)(mocks);
                           return makeEvent(R"({"ref": ["k0", "k1"], "target": ["v0", "v1"]})");
                       })),
        TransformT(R"({"target": ["v2"], "ref": ["k0", "k1"]})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdbGetValue("dbname", "k0", R"("v0")", nullptr)(mocks);
                           expectKvdbGetValue("dbname", "k1", R"("v1")", nullptr)(mocks);
                           return makeEvent(R"({"ref": ["k0", "k1"], "target": ["v2", "v0", "v1"]})");
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({"ref": "notArray"})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({"ref": ["k0", 1]})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeRef("ref")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           expectKvdb("dbname")(mocks);
                           return None {};
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbGetValue("dbname", "k0", R"("v0")", nullptr)(mocks);
                           expectKvdbGetError("dbname", "k1")(mocks);
                           return None {};
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbGetValue("dbname", "k0", R"("v0")", nullptr)(mocks);
                           expectKvdbGetValue("dbname", "k1", R"("malformed"json")", nullptr)(mocks);
                           return None {};
                       })),
        TransformT(R"({})",
                   getOpBuilderKVDBGetArray(kvdbMock, SCOPE),
                   "target",
                   {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                   FAILURE(
                       [](const BuildersMocks& mocks)
                       {
                           expectKvdb("dbname")(mocks);
                           expectKvdbGetValue("dbname", "k0", R"(1)", nullptr)(mocks);
                           expectKvdbGetValue("dbname", "k1", R"("nonHomogeneus")", nullptr)(mocks);
                           return None {};
                       }))
        /*** BITMASK TO TABLE ***/

        ),
    testNameFormatter<TransformOperationTest>("KVDB"));
} // namespace transformoperatestest

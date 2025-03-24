#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/kvdb.hpp"
#include <kvdb/mockKvdbManager.hpp>

using namespace kvdb::mocks;

namespace
{
constexpr auto SCOPE = "test_scope";

template<typename... T>
auto customRefExpected(T... refs)
{
    return [=](const BuildersMocks& mocks)
    {
        if (sizeof...(refs) > 0)
        {
            EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        }
        else
        {
            EXPECT_CALL(*mocks.ctx, validator());
        }

        for (const auto& ref : {refs...})
        {
            EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        }

        return None {};
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

filterbuildtest::BuilderGetter getMatch()
{
    return []()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        return getOpBuilderKVDBMatch(kvdbMock, SCOPE);
    };
}

filterbuildtest::BuilderGetter getNotMatch()
{
    return []()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        return getOpBuilderKVDBNotMatch(kvdbMock, SCOPE);
    };
}

filterbuildtest::BuilderGetter getMatchExpectHandler(const std::string& name)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        return getOpBuilderKVDBMatch(kvdbMock, SCOPE);
    };
}

template<typename Behaviour>
filterbuildtest::BuilderGetter getMatchExpectHandler(const std::string& name, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        behaviour(kvdbHandlerMock);
        return getOpBuilderKVDBMatch(kvdbMock, SCOPE);
    };
}

filterbuildtest::BuilderGetter getNotMatchExpectHandler(const std::string& name)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        return getOpBuilderKVDBNotMatch(kvdbMock, SCOPE);
    };
}

template<typename Behaviour>
filterbuildtest::BuilderGetter getNotMatchExpectHandler(const std::string& name, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        behaviour(kvdbHandlerMock);
        return getOpBuilderKVDBNotMatch(kvdbMock, SCOPE);
    };
}

filterbuildtest::BuilderGetter getMatchExpectHandlerError(const std::string& name)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(base::Error {"error"}));
        return getOpBuilderKVDBMatch(kvdbMock, SCOPE);
    };
}

filterbuildtest::BuilderGetter getNotMatchExpectHandlerError(const std::string& name)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(base::Error {"error"}));
        return getOpBuilderKVDBNotMatch(kvdbMock, SCOPE);
    };
}

auto expectContainsKey(const std::string& name, const std::string& key, bool contains = true)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, contains(key)).WillOnce(testing::Return(contains));
    };
}

auto expectContainsError(const std::string& name, const std::string& key)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, contains(key)).WillOnce(testing::Return(base::Error {"error"}));
    };
}

template<typename TrBuilder>
transformbuildtest::BuilderGetter getTrBuilder(TrBuilder&& builder)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        return builder(kvdbMock, SCOPE);
    };
}

template<typename TrBuilder>
transformbuildtest::BuilderGetter getTrBuilderExpectHandler(TrBuilder&& builder, const std::string& name)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        return builder(kvdbMock, SCOPE);
    };
}

template<typename TrBuilder, typename Behaviour>
transformbuildtest::BuilderGetter
getTrBuilderExpectHandler(TrBuilder&& builder, const std::string& name, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        auto kvdbHandlerMock = std::make_shared<MockKVDBHandler>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(kvdbHandlerMock));
        behaviour(kvdbHandlerMock);
        return builder(kvdbMock, SCOPE);
    };
}

template<typename TrBuilder>
transformbuildtest::BuilderGetter getTrBuilderExpectHandlerError(TrBuilder&& builder, const std::string& name)
{
    return [=]()
    {
        auto kvdbMock = std::make_shared<MockKVDBManager>();
        EXPECT_CALL(*kvdbMock, getKVDBHandler(name, SCOPE)).WillOnce(testing::Return(base::Error {"error"}));
        return builder(kvdbMock, SCOPE);
    };
}

auto expectKvdbGetValue(const std::string& key, const std::string& value)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, get(key)).WillOnce(testing::Return(value));
    };
}

auto expectKvdbGetError(const std::string& key)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, get(key)).WillOnce(testing::Return(base::Error {"error"}));
    };
}

auto expectKvdbSet(const std::string& key, const std::string& jValue)
{
    json::Json value {jValue.c_str()};
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, set(key, value)).WillOnce(testing::Return(base::noError()));
    };
}

auto expectKvdbSetError(const std::string& key, const std::string& jValue)
{
    json::Json value {jValue.c_str()};
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, set(key, value)).WillOnce(testing::Return(base::Error {"error"}));
    };
}

auto expectKvdbDelete(const std::string& key)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, remove(key)).WillOnce(testing::Return(base::noError()));
    };
}

auto expectKvdbDeleteError(const std::string& key)
{
    return [=](const std::shared_ptr<MockKVDBHandler>& handler)
    {
        EXPECT_CALL(*handler, remove(key)).WillOnce(testing::Return(base::Error {"error"}));
    };
}

} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterBuilderWithDepsTest,
                         testing::Values(
                             /*** MATCH ***/
                             FilterDepsT({}, getMatch(), FAILURE()),
                             FilterDepsT({makeRef("ref")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"("name")")}, getMatchExpectHandler("name"), SUCCESS()),
                             FilterDepsT({makeValue(R"("name")"), makeValue(R"("value")")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(1)")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(1.1)")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(true)")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(null)")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"([])")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"({})")}, getMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"("name")")}, getMatchExpectHandlerError("name"), FAILURE()),
                             /*** NOT MATCH ***/
                             FilterDepsT({}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeRef("ref")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"("name")")}, getNotMatchExpectHandler("name"), SUCCESS()),
                             FilterDepsT({makeValue(R"("name")"), makeValue(R"("value")")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(1)")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(1.1)")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(true)")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"(null)")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"([])")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"({})")}, getNotMatch(), FAILURE()),
                             FilterDepsT({makeValue(R"("name")")}, getNotMatchExpectHandlerError("name"), FAILURE())),
                         testNameFormatter<FilterBuilderWithDepsTest>("KVDB"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationWithDepsTest,
    testing::Values(
        /*** MATCH ***/
        FilterDepsT(R"({"target": "key"})",
                    getMatchExpectHandler("dbname", expectContainsKey("dbname", "key", true)),
                    "target",
                    {makeValue(R"("dbname")")},
                    SUCCESS()),
        FilterDepsT(R"({"target": "key"})",
                    getMatchExpectHandler("dbname"),
                    "notTarget",
                    {makeValue(R"("dbname")")},
                    FAILURE()),
        FilterDepsT(
            R"({"target": 1})", getMatchExpectHandler("dbname"), "target", {makeValue(R"("dbname")")}, FAILURE()),
        FilterDepsT(R"({"target": "key"})",
                    getMatchExpectHandler("dbname", expectContainsError("dbname", "key")),
                    "target",
                    {makeValue(R"("dbname")")},
                    FAILURE()),
        FilterDepsT(R"({"target": "key"})",
                    getMatchExpectHandler("dbname", expectContainsKey("dbname", "key", false)),
                    "target",
                    {makeValue(R"("dbname")")},
                    FAILURE()),
        /*** NOT MATCH ***/
        FilterDepsT(R"({"target": "key"})",
                    getNotMatchExpectHandler("dbname", expectContainsKey("dbname", "key", false)),
                    "target",
                    {makeValue(R"("dbname")")},
                    SUCCESS()),
        FilterDepsT(R"({"target": "key"})",
                    getNotMatchExpectHandler("dbname"),
                    "notTarget",
                    {makeValue(R"("dbname")")},
                    FAILURE()),
        FilterDepsT(
            R"({"target": 1})", getNotMatchExpectHandler("dbname"), "target", {makeValue(R"("dbname")")}, FAILURE()),
        FilterDepsT(R"({"target": "key"})",
                    getNotMatchExpectHandler("dbname", expectContainsError("dbname", "key")),
                    "target",
                    {makeValue(R"("dbname")")},
                    FAILURE()),
        FilterDepsT(R"({"target": "key"})",
                    getNotMatchExpectHandler("dbname", expectContainsKey("dbname", "key", true)),
                    "target",
                    {makeValue(R"("dbname")")},
                    FAILURE())),
    testNameFormatter<FilterOperationWithDepsTest>("KVDB"));
} // namespace filteroperatestest

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderWithDepsTest,
    testing::Values(
        /*** GET ***/
        TransformDepsT({}, getTrBuilder(getOpBuilderKVDBGet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderKVDBGet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname"),
                       SUCCESS()),
        TransformDepsT({makeRef("ref"), makeValue(R"("key")")}, getTrBuilder(getOpBuilderKVDBGet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname"),
                       SUCCESS(customRefExpected("ref", "targetField"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderKVDBGet),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(1)")}, getTrBuilder(getOpBuilderKVDBGet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname"),
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderKVDBGet),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandlerError(getOpBuilderKVDBGet, "dbname"),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderKVDBGet),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** GET MERGE ***/
        TransformDepsT({}, getTrBuilder(getOpBuilderKVDBGetMerge), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderKVDBGetMerge), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname"),
                       SUCCESS()),
        TransformDepsT({makeRef("ref"), makeValue(R"("key")")}, getTrBuilder(getOpBuilderKVDBGetMerge), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname"),
                       SUCCESS(customRefExpected("ref", "targetField"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderKVDBGetMerge),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(1)")},
                       getTrBuilder(getOpBuilderKVDBGetMerge),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname"),
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderKVDBGetMerge),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandlerError(getOpBuilderKVDBGetMerge, "dbname"),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderKVDBGetMerge),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** GET MERGE RECURSIVE***/
        TransformDepsT({}, getTrBuilder(getOpBuilderKVDBGetMergeRecursive), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderKVDBGetMergeRecursive), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetMergeRecursive, "dbname"),
                       SUCCESS()),
        TransformDepsT({makeRef("ref"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderKVDBGetMergeRecursive),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetMergeRecursive, "dbname"),
                       SUCCESS(customRefExpected("ref", "targetField"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderKVDBGetMergeRecursive),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(1)")},
                       getTrBuilder(getOpBuilderKVDBGetMergeRecursive),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetMergeRecursive, "dbname"),
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderKVDBGetMergeRecursive),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandlerError(getOpBuilderKVDBGetMergeRecursive, "dbname"),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderKVDBGetMergeRecursive),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** SET ***/
        TransformDepsT({}, getTrBuilder(getOpBuilderKVDBSet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderKVDBSet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")}, getTrBuilder(getOpBuilderKVDBSet), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       SUCCESS()),
        TransformDepsT(
            {makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")"), makeValue(R"("other")")},
            getTrBuilder(getOpBuilderKVDBSet),
            FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"(1)")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       SUCCESS()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(1)"), makeValue(R"("value")")},
                       getTrBuilder(getOpBuilderKVDBSet),
                       FAILURE()),
        TransformDepsT({makeValue(R"(1)"), makeValue(R"("key")"), makeValue(R"("value")")},
                       getTrBuilder(getOpBuilderKVDBSet),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       SUCCESS(customRefExpected("keyRef", "targetField"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               jTypeRefExpected("keyRef", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                       getTrBuilder(getOpBuilderKVDBSet),
                       FAILURE(jTypeRefExpected("keyRef", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                       getTrBuilderExpectHandlerError(getOpBuilderKVDBSet, "dbname"),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                       getTrBuilder(getOpBuilderKVDBSet),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** DELETE ***/
        TransformDepsT({}, getTrBuilder(getOpBuilderKVDBDelete), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderKVDBDelete), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname"),
                       SUCCESS()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname"),
                       SUCCESS(customRefExpected("ref", "targetField"))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname"),
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderKVDBDelete),
                       FAILURE()),
        TransformDepsT({makeValue(R"(1)"), makeValue(R"("key")")}, getTrBuilder(getOpBuilderKVDBDelete), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(1)")}, getTrBuilder(getOpBuilderKVDBDelete), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderKVDBDelete),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilderExpectHandlerError(getOpBuilderKVDBDelete, "dbname"),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderKVDBDelete),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** GET ARRAY ***/
        TransformDepsT({}, getTrBuilder(getOpBuilderKVDBGetArray), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderKVDBGetArray), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray, "dbname"),
                       SUCCESS()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray, "dbname"),
                       SUCCESS(customRefExpected("ref"))),
        TransformDepsT({makeValue(R"(1)"), makeValue(R"(["k0", "k1"])")},
                       getTrBuilder(getOpBuilderKVDBGetArray),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderKVDBGetArray),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("not an array")")},
                       getTrBuilder(getOpBuilderKVDBGetArray),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray, "dbname"),
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, isArray(DotPath("ref"))).WillOnce(testing::Return(true));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderKVDBGetArray),
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               EXPECT_CALL(*mocks.validator, isArray(DotPath("ref"))).WillOnce(testing::Return(true));
                               jTypeRefExpected("ref", json::Json::Type::Number)(mocks);
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderKVDBGetArray),
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
                               EXPECT_CALL(*mocks.validator, isArray(DotPath("ref"))).WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       getTrBuilderExpectHandlerError(getOpBuilderKVDBGetArray, "dbname"),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderKVDBGetArray),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** BITMASK TO TABLE ***/
        TransformDepsT({}, getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"001":"val1"})")),
                       SUCCESS(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"001":"val1"})")),
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               jTypeRefExpected("targetField", json::Json::Type::String)(mocks);
                               EXPECT_CALL(*mocks.validator, isArray(DotPath("targetField")))
                                   .WillOnce(testing::Return(true));
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"001":"val1"})")),
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               jTypeRefExpected("ref", json::Json::Type::String)(mocks);
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeRef("ref"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref"), makeValue(R"("other")")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeValue(R"(1)"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"(1)"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE()),
        TransformDepsT(
            {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
            getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
            FAILURE(
                [](const BuildersMocks& mocks)
                {
                    EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
                    EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField"))).WillOnce(testing::Return(true));
                    EXPECT_CALL(*mocks.validator, isArray(DotPath("targetField"))).WillOnce(testing::Return(false));
                    return None {};
                })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               jTypeRefExpected("targetField", json::Json::Type::Number)(mocks);
                               EXPECT_CALL(*mocks.validator, isArray(DotPath("targetField")))
                                   .WillOnce(testing::Return(true));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               jTypeRefExpected("ref", json::Json::Type::Boolean)(mocks);
                               EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandlerError(getOpBuilderHelperKVDBDecodeBitmask, "dbname"),
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("targetField", "ref")(mocks);
                               return None {};
                           })),
        TransformDepsT(
            {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
            getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask, "dbname", expectKvdbGetError("key")),
            FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"("malformed"Json")")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(
                           getOpBuilderHelperKVDBDecodeBitmask, "dbname", expectKvdbGetValue("key", R"("notObject")")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(
                           getOpBuilderHelperKVDBDecodeBitmask, "dbname", expectKvdbGetValue("key", R"({})")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"":"emptyKey"})")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"-0001":"negativeKey"})")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"notNumber":"value"})")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     auto maxDigits =
                                                         std::to_string(std::numeric_limits<uint64_t>::max());
                                                     maxDigits += "1";
                                                     auto value = fmt::format(R"({{"{}": "value"}})", maxDigits);
                                                     expectKvdbGetValue("key", value)(handler);
                                                 }),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"00001": "heterogeneus", "00002": 2})")),
                       FAILURE(customRefExpected("targetField", "ref"))),
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       getTrBuilder(getOpBuilderHelperKVDBDecodeBitmask),
                       FAILURE(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           }))),
    testNameFormatter<TransformBuilderWithDepsTest>("KVDB"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationWithDepsTest,
    testing::Values(
        /*** GET ***/
        TransformDepsT(
            R"({})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname", expectKvdbGetValue("key", R"("value")")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")")},
            SUCCESS(makeEvent(R"({"target": "value"})"))),
        TransformDepsT(
            R"({"ref": "key"})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname", expectKvdbGetValue("key", R"("value")")),
            "target",
            {makeValue(R"("dbname")"), makeRef("ref")},
            SUCCESS(
                [](const BuildersMocks& mocks)
                {
                    customRefExpected("ref", "target")(mocks);
                    return makeEvent(R"({"ref": "key", "target": "value"})");
                })),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref", "target"))),
        TransformDepsT(R"({"ref": 1})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref", "target"))),
        TransformDepsT(R"({"ref": "key"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname", expectKvdbGetError("key")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref", "target"))),
        TransformDepsT(
            R"({"ref": "key"})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGet, "dbname", expectKvdbGetValue("key", "malformedJsonValue")),
            "target",
            {makeValue(R"("dbname")"), makeRef("ref")},
            FAILURE(customRefExpected("target", "ref"))),
        TransformDepsT(R"({"ref": "key"})",
                       getTrBuilderExpectHandler(
                           getOpBuilderKVDBGet, "dbname", expectKvdbGetValue("key", R"({"notAllowed": "value"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref", "target")(mocks);
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                                   .WillOnce(testing::Return(true));
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.notAllowed")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** GET MERGE ***/
        TransformDepsT(
            R"({"target": [0, 2]})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname", expectKvdbGetValue("key", R"([1, 3])")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")")},
            SUCCESS(makeEvent(R"({"target": [0, 2, 1, 3]})"))),
        TransformDepsT(R"({"target": {"a": 0, "b": 2}, "ref": "key"})",
                       getTrBuilderExpectHandler(
                           getOpBuilderKVDBGetMerge, "dbname", expectKvdbGetValue("key", R"({"b": 3, "c": 4})")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref", "target")(mocks);
                               return makeEvent(R"({"target": {"a": 0, "b": 3, "c": 4}, "ref": "key"})");
                           })),
        TransformDepsT(
            R"({})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname", expectKvdbGetValue("key", R"([1, 3])")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")")},
            FAILURE()),
        TransformDepsT(
            R"({"target": []})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname", expectKvdbGetValue("key", R"({"a": 0})")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")")},
            FAILURE()),
        TransformDepsT(
            R"({"target": "value"})",
            getTrBuilderExpectHandler(getOpBuilderKVDBGetMerge, "dbname", expectKvdbGetValue("key", R"("othervalue")")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")")},
            FAILURE()),
        TransformDepsT(R"({"ref": "key"})",
                       getTrBuilderExpectHandler(
                           getOpBuilderKVDBGetMerge, "dbname", expectKvdbGetValue("key", R"({"notAllowed": "value"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref", "target")(mocks);
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                                   .WillOnce(testing::Return(true));
                               EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.notAllowed")))
                                   .WillOnce(testing::Return(false));
                               return None {};
                           })),
        /*** SET ***/
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname", expectKvdbSet("key", R"("value")")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
                       SUCCESS(makeEvent(R"({"target": true})"))),
        TransformDepsT(R"({"ref": "key"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname", expectKvdbSet("key", R"("value")")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref", "target")(mocks);
                               return makeEvent(R"({"ref": "key", "target": true})");
                           })),
        TransformDepsT(R"({"ref": "value"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname", expectKvdbSet("key", R"("value")")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       SUCCESS(makeEvent(R"({"ref": "value", "target": true})"))),
        TransformDepsT(R"({"keyRef": "key", "valueRef": "value"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname", expectKvdbSet("key", R"("value")")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("keyRef"), makeRef("valueRef")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("keyRef", "target")(mocks);
                               return makeEvent(R"({"keyRef": "key", "valueRef": "value", "target": true})");
                           })),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("keyRef"), makeValue(R"("value")")},
                       FAILURE(customRefExpected("keyRef", "target"))),
        TransformDepsT(R"({"ref": 1})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")},
                       FAILURE(customRefExpected("ref", "target"))),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       FAILURE()),
        TransformDepsT(
            R"({"ref": "value"})",
            getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname", expectKvdbSetError("key", R"("value")")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
            FAILURE()),
        TransformDepsT(
            R"({})",
            getTrBuilderExpectHandler(getOpBuilderKVDBSet, "dbname", expectKvdbSetError("key", R"("value")")),
            "target",
            {makeValue(R"("dbname")"), makeValue(R"("key")"), makeValue(R"("value")")},
            FAILURE()),
        /*** DELETE ***/
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname", expectKvdbDelete("key")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")")},
                       SUCCESS(makeEvent(R"({"target": true})"))),
        TransformDepsT(R"({"ref": "key"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname", expectKvdbDelete("key")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref", "target")(mocks);
                               return makeEvent(R"({"ref": "key", "target": true})");
                           })),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref", "target"))),
        TransformDepsT(R"({"ref": 1})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref", "target"))),
        TransformDepsT(R"({"ref": "key"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBDelete, "dbname", expectKvdbDeleteError("key")),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref", "target"))),
        /*** GET ARRAY ***/
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"("v0")")(handler);
                                                     expectKvdbGetValue("k1", R"("v1")")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.validator, validate(DotPath("target"), testing::_))
                                   .WillOnce(testing::Return(schemf::ValidationResult()));
                               return makeEvent(R"({"target": ["v0", "v1"]})");
                           })),
        TransformDepsT(R"({"target": ["v2"]})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"("v0")")(handler);
                                                     expectKvdbGetValue("k1", R"("v1")")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       SUCCESS(
                           [](const auto& mocks)
                           {
                               EXPECT_CALL(*mocks.validator, validate(DotPath("target"), testing::_))
                                   .WillOnce(testing::Return(schemf::ValidationResult()));
                               return makeEvent(R"({"target": ["v2", "v0", "v1"]})");
                           })),
        TransformDepsT(R"({"ref": ["k0", "k1"]})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"("v0")")(handler);
                                                     expectKvdbGetValue("k1", R"("v1")")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref")(mocks);
                               EXPECT_CALL(*mocks.validator, validate(DotPath("target"), testing::_))
                                   .WillOnce(testing::Return(schemf::ValidationResult()));
                               return makeEvent(R"({"ref": ["k0", "k1"], "target": ["v0", "v1"]})");
                           })),
        TransformDepsT(R"({"target": ["v2"], "ref": ["k0", "k1"]})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"("v0")")(handler);
                                                     expectKvdbGetValue("k1", R"("v1")")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("ref")(mocks);
                               EXPECT_CALL(*mocks.validator, validate(DotPath("target"), testing::_))
                                   .WillOnce(testing::Return(schemf::ValidationResult()));
                               return makeEvent(R"({"ref": ["k0", "k1"], "target": ["v2", "v0", "v1"]})");
                           })),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT(R"({"ref": "notArray"})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT(R"({"ref": ["k0", 1]})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray, "dbname"),
                       "target",
                       {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE(customRefExpected("ref"))),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"("v0")")(handler);
                                                     expectKvdbGetError("k1")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       FAILURE()),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"("v0")")(handler);
                                                     expectKvdbGetValue("k1", R"("malformed"json")")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       FAILURE()),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderKVDBGetArray,
                                                 "dbname",
                                                 [](const std::shared_ptr<MockKVDBHandler>& handler)
                                                 {
                                                     expectKvdbGetValue("k0", R"(1)")(handler);
                                                     expectKvdbGetValue("k1", R"("nonHomogeneus")")(handler);
                                                 }),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"(["k0", "k1"])")},
                       FAILURE()),
        /*** BITMASK TO TABLE ***/
        TransformDepsT(R"({"ref": "0x1"})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("target", "ref")(mocks);
                               return makeEvent(R"({"ref": "0x1", "target": ["val1"]})");
                           })),
        TransformDepsT(R"({"ref": "0x2"})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"1": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("target", "ref")(mocks);
                               return makeEvent(R"({"ref": "0x2", "target": ["val1"]})");
                           })),
        TransformDepsT(R"({"ref": "0x3"})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1", "1": "val2"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("target", "ref")(mocks);
                               return makeEvent(R"({"ref": "0x3", "target": ["val1", "val2"]})");
                           })),
        TransformDepsT(R"({})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       FAILURE(customRefExpected("target", "ref"))),
        TransformDepsT(R"({"ref": 1})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       FAILURE(customRefExpected("target", "ref"))),
        TransformDepsT(R"({"ref": "nothexa"})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       FAILURE(customRefExpected("target", "ref"))),
        TransformDepsT(fmt::format(R"({{"ref": "0x{}"}})", std::string(std::numeric_limits<uint64_t>::digits + 1, '1')),
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       FAILURE(customRefExpected("target", "ref"))),
        TransformDepsT(R"({"ref": "0x1"})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"1": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       FAILURE(customRefExpected("target", "ref"))),
        TransformDepsT(R"({"ref": "0x3"})",
                       getTrBuilderExpectHandler(getOpBuilderHelperKVDBDecodeBitmask,
                                                 "dbname",
                                                 expectKvdbGetValue("key", R"({"0": "val1"})")),
                       "target",
                       {makeValue(R"("dbname")"), makeValue(R"("key")"), makeRef("ref")},
                       SUCCESS(
                           [](const BuildersMocks& mocks)
                           {
                               customRefExpected("target", "ref")(mocks);
                               return makeEvent(R"({"ref": "0x3", "target": ["val1"]})");
                           }))),
    testNameFormatter<TransformOperationWithDepsTest>("KVDB"));
} // namespace transformoperatestest

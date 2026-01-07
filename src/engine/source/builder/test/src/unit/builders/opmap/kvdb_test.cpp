#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/kvdb.hpp"

#include <kvdbstore/mockKvdbHandler.hpp>
#include <kvdbstore/mockKvdbManager.hpp>

using namespace builder::builders;
using namespace kvdbstore::mocks;

namespace
{

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrEq;
using ::testing::Throw;

// ---------------------------------------------------------------------
// Builders for kvdb_get
// ---------------------------------------------------------------------
auto getBuilder_KVDBGet()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();
        (void)kvdbHandler;
        return getOpBuilderKVDBGet(kvdbManager);
    };
}

auto getBuilder_KVDBGetExpectHandler(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        return getOpBuilderKVDBGet(kvdbManager);
    };
}

template<typename Behaviour>
auto getBuilder_KVDBGetExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        behaviour(kvdbHandler);

        return getOpBuilderKVDBGet(kvdbManager);
    };
}

auto getBuilder_KVDBGetExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));

        return getOpBuilderKVDBGet(kvdbManager);
    };
}

// ---------------------------------------------------------------------
// Builders for kvdb_get_merge
// ---------------------------------------------------------------------
auto mergeTargetSchemaNotMergeableExpected(const std::string& ref, schemf::Type type)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getType(DotPath(ref))).Times(AtLeast(1)).WillRepeatedly(testing::Return(type));

        return None {};
    };
}

auto mergeTargetObjectSchemaExpected(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getType(DotPath(ref))).WillOnce(testing::Return(schemf::Type::OBJECT));
        EXPECT_CALL(*mocks.validator, validate(DotPath(ref), _)).WillOnce(testing::Return(schemf::ValidationResult()));
        return None {};
    };
}

auto getBuilder_KVDBGetMerge()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();
        (void)kvdbHandler;
        return getOpBuilderKVDBGetMerge(kvdbManager);
    };
}

auto getBuilder_KVDBGetMergeExpectHandler(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        return getOpBuilderKVDBGetMerge(kvdbManager);
    };
}

template<typename Behaviour>
auto getBuilder_KVDBGetMergeExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        behaviour(kvdbHandler);

        return getOpBuilderKVDBGetMerge(kvdbManager);
    };
}

auto getBuilder_KVDBGetMergeExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));

        return getOpBuilderKVDBGetMerge(kvdbManager);
    };
}

// ---------------------------------------------------------------------
// Builders for kvdb_get_merge_recursive
// ---------------------------------------------------------------------
auto getBuilder_KVDBGetMergeRecursive()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();
        (void)kvdbHandler;
        return getOpBuilderKVDBGetMergeRecursive(kvdbManager);
    };
}

auto getBuilder_KVDBGetMergeRecursiveExpectHandler(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        return getOpBuilderKVDBGetMergeRecursive(kvdbManager);
    };
}

template<typename Behaviour>
auto getBuilder_KVDBGetMergeRecursiveExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        behaviour(kvdbHandler);

        return getOpBuilderKVDBGetMergeRecursive(kvdbManager);
    };
}

auto getBuilder_KVDBGetMergeRecursiveExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));

        return getOpBuilderKVDBGetMergeRecursive(kvdbManager);
    };
}

// ---------------------------------------------------------------------
// Builders for kvdb_get_array
// ---------------------------------------------------------------------
auto getBuilder_KVDBGetArray()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();
        (void)kvdbHandler;
        return getOpBuilderKVDBGetArray(kvdbManager);
    };
}

auto getBuilder_KVDBGetArrayExpectHandler(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        return getOpBuilderKVDBGetArray(kvdbManager);
    };
}

template<typename Behaviour>
auto getBuilder_KVDBGetArrayExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        behaviour(kvdbHandler);

        return getOpBuilderKVDBGetArray(kvdbManager);
    };
}

auto getBuilder_KVDBGetArrayExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));

        return getOpBuilderKVDBGetArray(kvdbManager);
    };
}

auto kvdbGetArrayTargetSchemaExpected(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(AtLeast(1));
        EXPECT_CALL(*mocks.validator, validate(DotPath(ref), _)).WillOnce(testing::Return(schemf::ValidationResult()));

        return None {};
    };
}

auto expectKvdbGetArrayValues(const std::vector<std::pair<std::string, std::string>>& keyValuePairs)
{
    return [=](const std::shared_ptr<MockIKVDBHandler>& kvdbHandler)
    {
        for (const auto& [key, jsonStr] : keyValuePairs)
        {
            auto value = std::make_shared<json::Json>(jsonStr.c_str());
            EXPECT_CALL(*kvdbHandler, get(StrEq(key)))
                .WillOnce(::testing::Invoke([value](const std::string&) -> const json::Json& { return *value; }));
        }
    };
}

// ---------------------------------------------------------------------
// Builder for kvdb_decode_bitmask
// ---------------------------------------------------------------------
auto getBuilder_KVDBDecodeBitmask()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        return getOpBuilderHelperKVDBDecodeBitmask(kvdbManager);
    };
}

template<typename Behaviour>
auto getBuilder_KVDBDecodeBitmaskExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));
        behaviour(kvdbHandler);

        return getOpBuilderHelperKVDBDecodeBitmask(kvdbManager);
    };
}

auto getBuilder_KVDBDecodeBitmaskExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));
        return getOpBuilderHelperKVDBDecodeBitmask(kvdbManager);
    };
}

auto expectKvdbGetMap(const std::string& mapKey, const std::string& jsonMapStr)
{
    return [=](const std::shared_ptr<MockIKVDBHandler>& kvdbHandler)
    {
        auto value = std::make_shared<json::Json>(jsonMapStr.c_str());
        EXPECT_CALL(*kvdbHandler, get(StrEq(mapKey)))
            .WillOnce(::testing::Invoke([value](const std::string&) -> const json::Json& { return *value; }));
    };
}

// ---------------------------------------------------------------------
// Builders for filters: kvdb_match / kvdb_not_match
// ---------------------------------------------------------------------

// Plain getters (no behaviour). Useful for arity/type errors or handler-throw scenarios.
auto getBuilder_KVDBMatch()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        return getOpBuilderKVDBMatch(kvdbManager);
    };
}

auto getBuilder_KVDBNotMatch()
{
    return []()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        return getOpBuilderKVDBNotMatch(kvdbManager);
    };
}

// Expect handler acquisition for a given DB and let caller inject handler expectations (contains(...))
template<typename Behaviour>
auto getBuilder_KVDBMatchExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        // The builder must fetch the handler for 'dbName'
        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));

        // Caller sets expectations over the handler
        behaviour(kvdbHandler);

        return getOpBuilderKVDBMatch(kvdbManager);
    };
}

template<typename Behaviour>
auto getBuilder_KVDBNotMatchExpectHandler(const std::string& dbName, Behaviour&& behaviour)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();
        auto kvdbHandler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName))).WillOnce(Return(kvdbHandler));
        behaviour(kvdbHandler);

        return getOpBuilderKVDBNotMatch(kvdbManager);
    };
}

// Simulate handler acquisition failure
auto getBuilder_KVDBMatchExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));

        return getOpBuilderKVDBMatch(kvdbManager);
    };
}

auto getBuilder_KVDBNotMatchExpectHandlerError(const std::string& dbName)
{
    return [=]()
    {
        auto kvdbManager = std::make_shared<MockIKVDBManager>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(_, StrEq(dbName)))
            .WillOnce(Throw(std::runtime_error("getKVDBHandler error")));

        return getOpBuilderKVDBNotMatch(kvdbManager);
    };
}

// Behaviour helper: define expected 'contains(key)' result
auto expectContains(const std::string& key, bool found)
{
    return [=](const std::shared_ptr<MockIKVDBHandler>& kvdbHandler)
    {
        EXPECT_CALL(*kvdbHandler, contains(StrEq(key))).WillOnce(Return(found));
    };
}

// ---------------------------------------------------------------------
// Custom expected behaviours
// ---------------------------------------------------------------------
auto eventOnlyExpected(base::Event result)
{
    return [=](const BuildersMocks&)
    {
        return result;
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

auto customRefExpected(json::Json value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));

        return value;
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
        EXPECT_CALL(*mocks.ctx, validator()).Times(AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(ref))).WillOnce(testing::Return(jType));

        return None {};
    };
}

auto expectKvdbGetValue(const std::string& key, const std::string& jsonStr)
{
    return [=](const std::shared_ptr<MockIKVDBHandler>& kvdbHandler)
    {
        auto value = std::make_shared<json::Json>(jsonStr.c_str());
        EXPECT_CALL(*kvdbHandler, get(StrEq(key)))
            .WillOnce(::testing::Invoke([value](const std::string&) -> const json::Json& { return *value; }));
    };
}

auto expectKvdbGetOutOfRange(const std::string& key)
{
    return [=](const std::shared_ptr<MockIKVDBHandler>& kvdbHandler)
    {
        EXPECT_CALL(*kvdbHandler, get(StrEq(key))).WillOnce(Throw(std::out_of_range("key not found")));
    };
}

// ---------------------------------------------------------------------
// KVDB Availability helpers
// ---------------------------------------------------------------------
auto kvdbNotDeclared(const std::string& dbName)
{
    return [=](const BuildersMocks& mocks)
    {
        static Context ctx;
        ctx.assetName = "test/asset";
        ctx.policyName = "test/policy";
        ctx.availableKvdbs = std::unordered_map<std::string, bool> {};

        ON_CALL(*mocks.ctx, context()).WillByDefault(testing::ReturnRef(ctx));
        ON_CALL(*mocks.ctx, isKvdbAvailable(testing::_)).WillByDefault(testing::Return(std::make_pair(false, false)));

        return None {};
    };
}

auto kvdbDisabled(const std::string& dbName)
{
    return [=](const BuildersMocks& mocks)
    {
        static Context ctx;
        ctx.assetName = "test/asset";
        ctx.policyName = "test/policy";
        ctx.availableKvdbs = std::unordered_map<std::string, bool> {{dbName, false}};

        ON_CALL(*mocks.ctx, context()).WillByDefault(testing::ReturnRef(ctx));
        ON_CALL(*mocks.ctx, isKvdbAvailable(dbName)).WillByDefault(testing::Return(std::make_pair(true, false)));

        return None {};
    };
}

auto kvdbEnabled(const std::string& dbName)
{
    return [=](const BuildersMocks& mocks)
    {
        static Context ctx;
        ctx.assetName = "test/asset";
        ctx.policyName = "test/policy";
        ctx.availableKvdbs = std::unordered_map<std::string, bool> {{dbName, true}};

        ON_CALL(*mocks.ctx, context()).WillByDefault(testing::ReturnRef(ctx));
        ON_CALL(*mocks.ctx, isKvdbAvailable(dbName)).WillByDefault(testing::Return(std::make_pair(true, true)));

        return None {};
    };
}

} // namespace

// =====================================================================
// Builder tests
// =====================================================================
namespace transformbuildtest
{

INSTANTIATE_TEST_SUITE_P(KVDBGet_Builder,
                         TransformBuilderWithDepsTest,
                         testing::Values(
                             // Invalid number of arguments
                             TransformDepsT({}, getBuilder_KVDBGet(), FAILURE()),
                             TransformDepsT({makeValue(R"("dbname")")}, getBuilder_KVDBGet(), FAILURE()),
                             TransformDepsT({makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")},
                                            getBuilder_KVDBGet(),
                                            FAILURE()),

                             // Second argument not string
                             TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
                             TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(jTypeRefExpected("ref", json::Json::Type::Boolean))),
                             TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(jTypeRefExpected("ref", json::Json::Type::Array))),
                             TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(jTypeRefExpected("ref", json::Json::Type::Object))),
                             TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(jTypeRefExpected("ref", json::Json::Type::Null))),

                             // First argument not string
                             TransformDepsT({makeRef("ref"), makeValue(R"("key")")}, getBuilder_KVDBGet(), FAILURE()),
                             TransformDepsT({makeRef("ref"), makeRef("ref")}, getBuilder_KVDBGet(), FAILURE()),

                             // Successful build
                             TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGet(),
                                            SUCCESS(customRefExpected("targetField"))),

                             // Errors getting KVDB handler
                             TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGetExpectHandlerError("dbname"),
                                            FAILURE())),
                         testNameFormatter<TransformBuilderWithDepsTest>("KVDBGet"));

INSTANTIATE_TEST_SUITE_P(
    KVDBGetMerge_Builder,
    TransformBuilderWithDepsTest,
    testing::Values(
        // Invalid number of arguments
        TransformDepsT({}, getBuilder_KVDBGetMerge(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getBuilder_KVDBGetMerge(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("value")")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE()),

        // Second argument not string (reference with wrong json type in schema)
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Boolean))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Array))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Object))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Null))),

        // First argument not string
        TransformDepsT({makeRef("ref"), makeValue(R"("key")")}, getBuilder_KVDBGetMerge(), FAILURE()),
        TransformDepsT({makeRef("ref"), makeRef("ref")}, getBuilder_KVDBGetMerge(), FAILURE()),

        // Target field in schema is not object/array -> build error
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMerge(),
                       FAILURE(mergeTargetSchemaNotMergeableExpected("targetField", schemf::Type::KEYWORD))),

        // Successful build (no schema for targetField)
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMerge(),
                       SUCCESS(customRefExpected("targetField"))),

        // Successful build with targetField typed as object in schema
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMerge(),
                       SUCCESS(mergeTargetObjectSchemaExpected("targetField"))),

        // Errors getting KVDB handler
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMergeExpectHandlerError("dbname"),
                       FAILURE())),
    testNameFormatter<TransformBuilderWithDepsTest>("KVDBGetMerge"));

INSTANTIATE_TEST_SUITE_P(
    KVDBGetMergeRecursive_Builder,
    TransformBuilderWithDepsTest,
    testing::Values(
        // Invalid number of arguments
        TransformDepsT({}, getBuilder_KVDBGetMergeRecursive(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getBuilder_KVDBGetMergeRecursive(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref"), makeValue(R"("extra")")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE()),

        // First argument is not a string
        TransformDepsT({makeRef("ref"), makeValue(R"("key")")}, getBuilder_KVDBGetMergeRecursive(), FAILURE()),
        TransformDepsT({makeRef("ref"), makeRef("ref")}, getBuilder_KVDBGetMergeRecursive(), FAILURE()),

        // Second argument is a reference but schema type is not string
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Number))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Boolean))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Array))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Object))),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("ref")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE(jTypeRefExpected("ref", json::Json::Type::Null))),

        // Target field in schema is not object/array -> build error
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMergeRecursive(),
                       FAILURE(mergeTargetSchemaNotMergeableExpected("targetField", schemf::Type::KEYWORD))),

        // Error getting KVDB handler -> build error
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMergeRecursiveExpectHandlerError("dbname"),
                       FAILURE()),

        // Successful build when target field is not present in schema
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("key")")},
                       getBuilder_KVDBGetMergeRecursive(),
                       SUCCESS(customRefExpected("targetField")))),
    testNameFormatter<TransformBuilderWithDepsTest>("KVDBGetMergeRecursive"));

INSTANTIATE_TEST_SUITE_P(
    KVDBGetArray_Builder,
    TransformBuilderWithDepsTest,
    testing::Values(
        // Invalid number of arguments
        TransformDepsT({}, getBuilder_KVDBGetArray(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")")}, getBuilder_KVDBGetArray(), FAILURE()),
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keys"), makeValue(R"("extra")")},
                       getBuilder_KVDBGetArray(),
                       FAILURE()),

        // First argument not string -> failure
        TransformDepsT({makeRef("ref"), makeRef("keys")}, getBuilder_KVDBGetArray(), FAILURE()),

        // Second argument should be a reference (keys source), not a literal value
        TransformDepsT({makeValue(R"("dbname")"), makeValue(R"("keys")")}, getBuilder_KVDBGetArray(), FAILURE()),

        // Successful build: db name literal + keys reference
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keys")},
                       getBuilder_KVDBGetArray(),
                       SUCCESS(kvdbGetArrayTargetSchemaExpected("targetField"))),

        // Error retrieving KVDB handler
        TransformDepsT({makeValue(R"("dbname")"), makeRef("keys")},
                       getBuilder_KVDBGetArrayExpectHandlerError("dbname"),
                       FAILURE())),
    testNameFormatter<TransformBuilderWithDepsTest>("KVDBGetArray"));

INSTANTIATE_TEST_SUITE_P(
    KVDBDecodeBitmask_Builder,
    TransformBuilderWithDepsTest,
    testing::Values(
        // Invalid arity
        TransformDepsT({}, getBuilder_KVDBDecodeBitmask(), FAILURE()),
        TransformDepsT({makeValue(R"("dbm")")}, getBuilder_KVDBDecodeBitmask(), FAILURE()),
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("map")")}, getBuilder_KVDBDecodeBitmask(), FAILURE()),
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("map")"), makeValue(R"("mask")")},
                       getBuilder_KVDBDecodeBitmask(),
                       FAILURE()),

        // OK: build (valid map object with homogeneous values and numeric-string keys)
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm",
                                                                 expectKvdbGetMap("bit_map", R"({"0":"A","3":"B"})")),
                       SUCCESS()),

        // Error: getKVDBHandler throws
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       getBuilder_KVDBDecodeBitmaskExpectHandlerError("dbm"),
                       FAILURE()),

        // Error: map value is not an object
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm", expectKvdbGetMap("bit_map", R"(["A","B"])")),
                       FAILURE()),

        // Error: empty object
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm", expectKvdbGetMap("bit_map", R"({})")),
                       FAILURE()),

        // Error: non-numeric key
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm", expectKvdbGetMap("bit_map", R"({"x":"A"})")),
                       FAILURE()),

        // Error: heterogeneous value types
        TransformDepsT({makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm",
                                                                 expectKvdbGetMap("bit_map", R"({"0":"A","1":42})")),
                       FAILURE())),
    testNameFormatter<TransformBuilderWithDepsTest>("HelperKVDBDecodeBitmask"));

} // namespace transformbuildtest

// =====================================================================
// Operation tests
// =====================================================================
namespace transformoperatestest
{

INSTANTIATE_TEST_SUITE_P(
    KVDBGet_Operation,
    TransformOperationWithDepsTest,
    testing::Values(
        // Key as value. Read successful (string)
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname", expectKvdbGetValue("k1", R"("value")")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":"value"})")))),

        // Key as reference. Field not present in event -> failure
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname"),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeRef("ref")},
                       FAILURE()),

        // Key not found in DB (std::out_of_range) -> failure
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname", expectKvdbGetOutOfRange("missing")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("missing")")},
                       FAILURE(customRefExpected("targetField"))),

        // Object value
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname", expectKvdbGetValue("k_obj", R"({"a":1,"b":[2,3]})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_obj")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{"a":1,"b":[2,3]}})")))),

        // Number value
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname", expectKvdbGetValue("k_num", R"(42)")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_num")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":42})")))),

        // Boolean value
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname", expectKvdbGetValue("k_bool", R"(true)")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_bool")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":true})")))),

        // Array value
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetExpectHandler("dbname", expectKvdbGetValue("k_arr", R"([10,20,30])")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_arr")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":[10,20,30]})")))),

        // Nested object value
        TransformDepsT(
            R"({})",
            getBuilder_KVDBGetExpectHandler("dbname",
                                            expectKvdbGetValue("k_nested", R"({"outer":{"inner":true,"num":5}})")),
            "targetField",
            std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_nested")")},
            SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{"outer":{"inner":true,"num":5}}})"))))

            ),
    testNameFormatter<TransformOperationWithDepsTest>("KVDBGet"));

INSTANTIATE_TEST_SUITE_P(
    KVDBGetMerge_Operation,
    TransformOperationWithDepsTest,
    testing::Values(
        // Target exists as object, DB value is object -> merge ok
        TransformDepsT(R"({"targetField":{"a":1}})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_obj", R"({"b":2})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_obj")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{"a":1,"b":2}})")))),

        // Target exists as array, DB value is array -> merge ok
        TransformDepsT(R"({"targetField":[1,2]})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_arr", R"([3,4])")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_arr")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":[1,2,3,4]})")))),

        // Both target and DB value are empty object/array
        TransformDepsT(R"({"targetField":{}})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_obj", R"({})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_obj")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{}})")))),

        TransformDepsT(R"({"targetField":[]})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_arr", R"([])")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_arr")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":[]})")))),

        // Target exists as object, DB value is empty object/array -> merge ok
        TransformDepsT(R"({"targetField":{"a":1}})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_obj", R"({})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_obj")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{"a":1}})")))),

        // Target does not exist in event -> failureTrace1
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_obj", R"({"b":2})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_obj")")},
                       FAILURE(customRefExpected("targetField"))),

        // Target exists but type mismatch (event: number, DB: object)
        TransformDepsT(R"({"targetField":1})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_obj", R"({"b":2})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_obj")")},
                       FAILURE(customRefExpected("targetField"))),

        // DB value is not object/array (string) -> not mergeable
        TransformDepsT(R"({"targetField":{}})",
                       getBuilder_KVDBGetMergeExpectHandler("dbname", expectKvdbGetValue("k_str", R"("value")")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k_str")")},
                       FAILURE(customRefExpected("targetField")))),
    testNameFormatter<TransformOperationWithDepsTest>("KVDBGetMerge"));

INSTANTIATE_TEST_SUITE_P(
    KVDBGetMergeRecursive_Operation,
    TransformOperationWithDepsTest,
    testing::Values(
        // Key as value. Recursive merge into an existing object.
        TransformDepsT(R"({"targetField":{"a":1}})",
                       getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetValue("k1", R"({"b":2})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{"a":1,"b":2}})")))),

        // Key as reference. Recursive merge into an existing object.
        TransformDepsT(R"({"ref":"k1","targetField":{"a":1}})",
                       getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetValue("k1", R"({"b":2})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeRef("ref")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"ref":"k1","targetField":{"a":1,"b":2}})")))),

        // Both target and DB value have nested objects -> recursive merge
        TransformDepsT(
            R"({"targetField":{"a":1,"nested":{"x":10}}})",
            getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname",
                                                          expectKvdbGetValue("k1", R"({"b":2,"nested":{"y":20}})")),
            "targetField",
            std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
            SUCCESS(customRefExpected("targetField",
                                      makeEvent(R"({"targetField":{"a":1,"b":2,"nested":{"x":10,"y":20}}})")))),

        // Both target and DB value have nested arrays -> recursive merge
        TransformDepsT(
            R"({"targetField":{"a":1,"arr":[1,2]}})",
            getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetValue("k1", R"({"b":2,"arr":[3,4]})")),
            "targetField",
            std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
            SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{"a":1,"b":2,"arr":[1,2,3,4]}})")))),

        // Both target and DB value have nested object and array -> recursive merge
        TransformDepsT(R"({"targetField":{"obj":{"k":"v"},"arr":[1]}})",
                       getBuilder_KVDBGetMergeRecursiveExpectHandler(
                           "dbname", expectKvdbGetValue("k1", R"({"obj":{"new_k":"new_v"},"arr":[2,3]})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
                       SUCCESS(customRefExpected(
                           "targetField",
                           makeEvent(R"({"targetField":{"obj":{"k":"v","new_k":"new_v"},"arr":[1,2,3]}})")))),

        // Both target and DB value are empty object/array
        TransformDepsT(R"({"targetField":{}})",
                       getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetValue("k1", R"({})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
                       SUCCESS(customRefExpected("targetField", makeEvent(R"({"targetField":{}})")))),

        // Key as reference. Both target and DB value have nested arrays
        TransformDepsT(
            R"({"ref":"k1","targetField":{"a":1,"arr":[1,2]}})",
            getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetValue("k1", R"({"b":2,"arr":[3,4]})")),
            "targetField",
            std::vector<OpArg> {makeValue(R"("dbname")"), makeRef("ref")},
            SUCCESS(eventOnlyExpected(makeEvent(R"({"ref":"k1","targetField":{"a":1,"b":2,"arr":[1,2,3,4]}})")))),

        // Target field does not exist in the event -> operation failure (nothing merged)
        TransformDepsT(R"({"other":42})",
                       getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetValue("k1", R"({"b":2})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("k1")")},
                       FAILURE()),

        // KVDB get throws std::out_of_range -> operation failure
        TransformDepsT(R"({"targetField":{"a":1}})",
                       getBuilder_KVDBGetMergeRecursiveExpectHandler("dbname", expectKvdbGetOutOfRange("missing")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbname")"), makeValue(R"("missing")")},
                       FAILURE(customRefExpected("targetField")))

            ),
    testNameFormatter<TransformOperationWithDepsTest>("KVDBGetMergeRecursive"));

INSTANTIATE_TEST_SUITE_P(
    KVDBGetArray_Operation,
    TransformOperationWithDepsTest,
    testing::Values(
        // Ok -> array of strings
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetArrayExpectHandler(
                           "db", expectKvdbGetArrayValues({{"k1", R"("v1")"}, {"k2", R"("v2")"}})),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"(["k1","k2"])")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"targetField":["v1","v2"]})")))),

        // Ok -> array of objects
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetArrayExpectHandler(
                           "db", expectKvdbGetArrayValues({{"k1", R"({"a":1})"}, {"k2", R"({"b":2})"}})),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"(["k1","k2"])")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"targetField":[{"a":1},{"b":2}]})")))),

        // Ok -> array of booleans
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetArrayExpectHandler(
                           "db", expectKvdbGetArrayValues({{"k1", R"(true)"}, {"k2", R"(false)"}})),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"(["k1","k2"])")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"targetField":[true,false]})")))),

        // Ok -> empty array
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetArrayExpectHandler("db", [](auto) {}),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"([])")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"targetField":[]})")))),

        // Ok -> array of numbers
        TransformDepsT(
            R"({})",
            getBuilder_KVDBGetArrayExpectHandler("db", expectKvdbGetArrayValues({{"k1", R"(10)"}, {"k2", R"(20)"}})),
            "targetField",
            std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"(["k1","k2"])")},
            SUCCESS(eventOnlyExpected(makeEvent(R"({"targetField":[10,20]})")))),

        // Ok -> array from reference
        TransformDepsT(R"({"keys":["k1","k2"]})",
                       getBuilder_KVDBGetArrayExpectHandler(
                           "db", expectKvdbGetArrayValues({{"k1", R"("v1")"}, {"k2", R"("v2")"}})),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeRef("keys")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"keys":["k1","k2"],"targetField":["v1","v2"]})")))),

        // Ref missing keys
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetArrayExpectHandler("db", [](auto) {}),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeRef("keys")},
                       FAILURE()),

        // Heterogeneous (string vs number) -> failure
        TransformDepsT(
            R"({})",
            getBuilder_KVDBGetArrayExpectHandler("db", expectKvdbGetArrayValues({{"k1", R"("v1")"}, {"k2", R"(42)"}})),
            "targetField",
            std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"(["k1","k2"])")},
            FAILURE()),

        // Missing key -> failure
        TransformDepsT(R"({})",
                       getBuilder_KVDBGetArrayExpectHandler(
                           "db",
                           [](const std::shared_ptr<MockIKVDBHandler>& h)
                           { EXPECT_CALL(*h, get(StrEq("k1"))).WillOnce(Throw(std::out_of_range("missing"))); }),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("db")"), makeValue(R"(["k1"])")},
                       FAILURE())),
    testNameFormatter<TransformOperationWithDepsTest>("KVDBGetArray"));

INSTANTIATE_TEST_SUITE_P(
    KVDBDecodeBitmask_Operation,
    TransformOperationWithDepsTest,
    testing::Values(
        // OK: mask 0x9 -> bits 0 and 3 => ["A","B"]
        TransformDepsT(R"({"mask":"0x9"})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm",
                                                                 expectKvdbGetMap("bit_map", R"({"0":"A","3":"B"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"mask":"0x9","targetField":["A","B"]})")))),

        // OK: mask 0x1F -> bits 0,1,2,3,4 => ["A","B","C","D","E"]
        TransformDepsT(R"({"mask":"0x1F"})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler(
                           "dbm", expectKvdbGetMap("bit_map", R"({"0":"A","1":"B","2":"C","3":"D","4":"E"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"mask":"0x1F","targetField":["A","B","C","D","E"]})")))),

        // OK: mask 0x2 -> bit 1 => ["B"]
        TransformDepsT(R"({"mask":"0x2"})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler(
                           "dbm", expectKvdbGetMap("bit_map", R"({"0":"A","1":"B","2":"C"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       SUCCESS(eventOnlyExpected(makeEvent(R"({"mask":"0x2","targetField":["B"]})")))),

        // Missing 'mask' reference in event
        TransformDepsT(R"({})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm", expectKvdbGetMap("bit_map", R"({"0":"A"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       FAILURE()),

        // 'mask' exists but is not a string
        TransformDepsT(R"({"mask":123})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm", expectKvdbGetMap("bit_map", R"({"0":"A"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       FAILURE()),

        // 'mask' is not a valid hexadecimal string
        TransformDepsT(R"({"mask":"ZZZ"})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm", expectKvdbGetMap("bit_map", R"({"0":"A"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       FAILURE()),

        // mask == 0x0 => no bits set => empty result => failure
        TransformDepsT(R"({"mask":"0x0"})",
                       getBuilder_KVDBDecodeBitmaskExpectHandler("dbm",
                                                                 expectKvdbGetMap("bit_map", R"({"0":"A","3":"B"})")),
                       "targetField",
                       std::vector<OpArg> {makeValue(R"("dbm")"), makeValue(R"("bit_map")"), makeRef("mask")},
                       FAILURE())),
    testNameFormatter<TransformOperationWithDepsTest>("HelperKVDBDecodeBitmask"));

} // namespace transformoperatestest

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    KVDBFilters_Builder,
    FilterBuilderWithDepsTest,
    testing::Values(
        // ---------- KVDBMatch ----------
        // Invalid arity
        FilterDepsT({}, getBuilder_KVDBMatch(), FAILURE()),
        FilterDepsT({makeValue(R"("db")"), makeValue(R"("extra")")}, getBuilder_KVDBMatch(), FAILURE()),
        // First arg must be a string value, not a reference
        FilterDepsT({makeRef("db")}, getBuilder_KVDBMatch(), FAILURE()),
        // OK: handler fetched correctly (no contains() expected at build time)
        FilterDepsT({makeValue(R"("db")")}, getBuilder_KVDBMatchExpectHandler("db", [](auto) {}), SUCCESS()),
        // Handler acquisition error
        FilterDepsT({makeValue(R"("db")")}, getBuilder_KVDBMatchExpectHandlerError("db"), FAILURE()),
        // ---------- KVDBNotMatch ----------
        // Invalid arity
        FilterDepsT({}, getBuilder_KVDBNotMatch(), FAILURE()),
        FilterDepsT({makeValue(R"("db")"), makeValue(R"("extra")")}, getBuilder_KVDBNotMatch(), FAILURE()),
        // First arg must be a string value, not a reference
        FilterDepsT({makeRef("db")}, getBuilder_KVDBNotMatch(), FAILURE()),
        // OK: handler fetched correctly (no contains() expected at build time)
        FilterDepsT({makeValue(R"("db")")}, getBuilder_KVDBNotMatchExpectHandler("db", [](auto) {}), SUCCESS()),
        // Handler acquisition error
        FilterDepsT({makeValue(R"("db")")}, getBuilder_KVDBNotMatchExpectHandlerError("db"), FAILURE())),
    testNameFormatter<FilterBuilderWithDepsTest>("KVDBFilters"));

} // namespace filterbuildtest

namespace filteroperatestest
{

INSTANTIATE_TEST_SUITE_P(KVDBFilters_Operation,
                         FilterOperationWithDepsTest,
                         testing::Values(
                             // ---------- KVDBMatch ----------
                             // Success: key exists in DB
                             FilterDepsT(R"({"field":"K"})",
                                         getBuilder_KVDBMatchExpectHandler("db", expectContains("K", true)),
                                         "field",
                                         std::vector<OpArg> {makeValue(R"("db")")},
                                         SUCCESS()),

                             // Failure: key does not exist (shouldMatch = true)
                             FilterDepsT(R"({"field":"K"})",
                                         getBuilder_KVDBMatchExpectHandler("db", expectContains("K", false)),
                                         "field",
                                         std::vector<OpArg> {makeValue(R"("db")")},
                                         FAILURE()),

                             // ---------- KVDBNotMatch ----------
                             // Success: key is NOT present (shouldMatch = false)
                             FilterDepsT(R"({"field":"K"})",
                                         getBuilder_KVDBNotMatchExpectHandler("db", expectContains("K", false)),
                                         "field",
                                         std::vector<OpArg> {makeValue(R"("db")")},
                                         SUCCESS()),
                             // Failure: key is present (shouldMatch = false)
                             FilterDepsT(R"({"field":"K"})",
                                         getBuilder_KVDBNotMatchExpectHandler("db", expectContains("K", true)),
                                         "field",
                                         std::vector<OpArg> {makeValue(R"("db")")},
                                         FAILURE()),

                             // ---------- Common operation failures ----------
                             // Missing target field (no contains() expected)
                             FilterDepsT(R"({})",
                                         getBuilder_KVDBMatchExpectHandler("db", [](auto) {}),
                                         "field",
                                         std::vector<OpArg> {makeValue(R"("db")")},
                                         FAILURE()),
                             // Target field not a string (no contains() expected)
                             FilterDepsT(R"({"field":42})",
                                         getBuilder_KVDBMatchExpectHandler("db", [](auto) {}),
                                         "field",
                                         std::vector<OpArg> {makeValue(R"("db")")},
                                         FAILURE())),
                         testNameFormatter<FilterOperationWithDepsTest>("KVDBFilters"));

} // namespace filteroperatestest

namespace transformbuildtest
{

INSTANTIATE_TEST_SUITE_P(KVDBAvailability_Builder,
                         TransformBuilderWithDepsTest,
                         testing::Values(
                             // Test: KVDB not found in context
                             TransformDepsT({makeValue(R"("nonexistent_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(kvdbNotDeclared("nonexistent_db"))),
                             // Test: KVDB exists but is disabled
                             TransformDepsT({makeValue(R"("disabled_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGet(),
                                            FAILURE(kvdbDisabled("disabled_db"))),
                             // Test: KVDB exists and is enabled (with handler mock)
                             TransformDepsT({makeValue(R"("enabled_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGetExpectHandler("enabled_db"),
                                            SUCCESS(kvdbEnabled("enabled_db"))),
                             // Test: kvdb_get_merge with non-existent KVDB
                             TransformDepsT({makeValue(R"("nonexistent_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGetMerge(),
                                            FAILURE(kvdbNotDeclared("nonexistent_db"))),
                             // Test: kvdb_get_merge with disabled KVDB
                             TransformDepsT({makeValue(R"("disabled_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGetMerge(),
                                            FAILURE(kvdbDisabled("disabled_db"))),
                             // Test: kvdb_get_merge_recursive with non-existent KVDB
                             TransformDepsT({makeValue(R"("nonexistent_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGetMergeRecursive(),
                                            FAILURE(kvdbNotDeclared("nonexistent_db"))),
                             // Test: kvdb_get_merge_recursive with disabled KVDB
                             TransformDepsT({makeValue(R"("disabled_db")"), makeValue(R"("key")")},
                                            getBuilder_KVDBGetMergeRecursive(),
                                            FAILURE(kvdbDisabled("disabled_db"))),
                             // Test: kvdb_get_array with non-existent KVDB
                             TransformDepsT({makeValue(R"("nonexistent_db")"), makeRef("array")},
                                            getBuilder_KVDBGetArray(),
                                            FAILURE(kvdbNotDeclared("nonexistent_db"))),
                             // Test: kvdb_get_array with disabled KVDB
                             TransformDepsT({makeValue(R"("disabled_db")"), makeRef("array")},
                                            getBuilder_KVDBGetArray(),
                                            FAILURE(kvdbDisabled("disabled_db"))),
                             // Test: kvdb_decode_bitmask with non-existent KVDB
                             TransformDepsT({makeValue(R"("nonexistent_db")"), makeValue(R"("key")"), makeRef("mask")},
                                            getBuilder_KVDBDecodeBitmask(),
                                            FAILURE(kvdbNotDeclared("nonexistent_db"))),
                             // Test: kvdb_decode_bitmask with disabled KVDB
                             TransformDepsT({makeValue(R"("disabled_db")"), makeValue(R"("key")"), makeRef("mask")},
                                            getBuilder_KVDBDecodeBitmask(),
                                            FAILURE(kvdbDisabled("disabled_db")))),
                         testNameFormatter<TransformBuilderWithDepsTest>("KVDBAvailability"));

} // namespace transformbuildtest

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    KVDBAvailability_Filter,
    FilterBuilderWithDepsTest,
    testing::Values(
        // Test: kvdb_match with non-existent KVDB
        FilterDepsT({makeValue(R"("nonexistent_db")")},
                    getBuilder_KVDBMatch(),
                    FAILURE(kvdbNotDeclared("nonexistent_db"))),
        // Test: kvdb_match with disabled KVDB
        FilterDepsT({makeValue(R"("disabled_db")")}, getBuilder_KVDBMatch(), FAILURE(kvdbDisabled("disabled_db"))),
        // Test: kvdb_match with enabled KVDB (with handler mock)
        FilterDepsT({makeValue(R"("enabled_db")")},
                    getBuilder_KVDBMatchExpectHandler("enabled_db", [](auto) {}),
                    SUCCESS(kvdbEnabled("enabled_db"))),
        // Test: kvdb_not_match with non-existent KVDB
        FilterDepsT({makeValue(R"("nonexistent_db")")},
                    getBuilder_KVDBNotMatch(),
                    FAILURE(kvdbNotDeclared("nonexistent_db"))),
        // Test: kvdb_not_match with disabled KVDB
        FilterDepsT({makeValue(R"("disabled_db")")}, getBuilder_KVDBNotMatch(), FAILURE(kvdbDisabled("disabled_db"))),
        // Test: kvdb_not_match with enabled KVDB (with handler mock)
        FilterDepsT({makeValue(R"("enabled_db")")},
                    getBuilder_KVDBNotMatchExpectHandler("enabled_db", [](auto) {}),
                    SUCCESS(kvdbEnabled("enabled_db")))),
    testNameFormatter<FilterBuilderWithDepsTest>("KVDBAvailability"));

} // namespace filterbuildtest

// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
void expectValidatorAccess(const BuildersMocks& mocks)
{
    EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AnyNumber());
}

auto builderArrayRefNotInSchema(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(false));
        return None {};
    };
}

auto builderArrayRefNotArray(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(true));
        return None {};
    };
}

auto builderArrayRefWrongElement(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(refName)))
            .WillRepeatedly(testing::Return(json::Json::Type::String));
        return None {};
    };
}

auto builderArrayRefTyped(const std::string& refName, json::Json::Type jType)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(refName))).WillRepeatedly(testing::Return(jType));
        return None {};
    };
}

auto opArrayRefNotInSchemaSuccess(const std::string& refName, const json::Json& expectedJson)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(false));
        return expectedJson;
    };
}

auto opArrayRefNotInSchemaFailure(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(false));
        return None {};
    };
}

auto opArrayRefNotArray(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(true));
        return None {};
    };
}

// The usual argument list: array_to_object_changes($ModifiedProperties, 'Name', 'NewValue', 'OldValue')
std::vector<OpArg> defaultArgs()
{
    return {
        makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("NewValue")"), makeValue(R"("OldValue")")};
}

// The same argument list plus a fifth (mode) argument
std::vector<OpArg> argsWithMode(const OpArg& mode)
{
    auto args = defaultArgs();
    args.push_back(mode);
    return args;
}

} // namespace

// array_to_object_changes($array, 'key_path', 'new_value_path', 'old_value_path', ['raw_keys'])
// The paths are dot paths relative to each element of the array ('.' is the whole element).
namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayExtractKeyObj,
    MapBuilderTest,
    testing::Values(
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             SUCCESS(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("changes.new")"),
              makeValue(R"("changes.old")")},
             opBuilderHelperArrayExtractKeyObj,
             SUCCESS(builderArrayRefNotInSchema("ModifiedProperties"))),
        // A JSON pointer (leading '/') is rejected: paths are dot paths
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("/Name")"),
              makeValue(R"("NewValue")"),
              makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        /*** Arity ***/
        MapT({}, opBuilderHelperArrayExtractKeyObj, FAILURE()),
        MapT({makeRef("ModifiedProperties")}, opBuilderHelperArrayExtractKeyObj, FAILURE()),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("NewValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE()),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("NewValue")"),
              makeValue(R"("OldValue")"),
              makeValue(R"("raw_keys")"),
              makeValue(R"("raw_keys")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE()),
        /*** Argument kinds and types ***/
        MapT({makeValue(R"("ModifiedProperties")"),
              makeValue(R"("Name")"),
              makeValue(R"("NewValue")"),
              makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE()),
        MapT({makeRef("ModifiedProperties"), makeRef("Name"), makeValue(R"("NewValue")"), makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeRef("NewValue"), makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("NewValue")"), makeRef("OldValue")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"(1)"), makeValue(R"("NewValue")"), makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"(1)"), makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("NewValue")"), makeValue(R"(1)")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(
            {makeRef("ModifiedProperties"), makeValue(R"("")"), makeValue(R"("NewValue")"), makeValue(R"("OldValue")")},
            opBuilderHelperArrayExtractKeyObj,
            FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("")"), makeValue(R"("OldValue")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("NewValue")"), makeValue(R"("")")},
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        /*** Optional mode: only the literal 'raw_keys' is accepted ***/
        MapT(argsWithMode(makeValue(R"("raw_keys")")),
             opBuilderHelperArrayExtractKeyObj,
             SUCCESS(builderArrayRefNotInSchema("ModifiedProperties"))),
        // The old boolean flag is a build error
        MapT(argsWithMode(makeValue(R"(true)")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(argsWithMode(makeValue(R"(false)")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(argsWithMode(makeValue(R"("skip")")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(argsWithMode(makeValue(R"("RAW_KEYS")")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(argsWithMode(makeValue(R"("")")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(argsWithMode(makeValue(R"(1)")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT(argsWithMode(makeRef("raw_keys")),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        /*** Array ref type validation (getJsonType -> Object) ***/
        MapT(defaultArgs(), opBuilderHelperArrayExtractKeyObj, FAILURE(builderArrayRefNotArray("ModifiedProperties"))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefWrongElement("ModifiedProperties"))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             SUCCESS(builderArrayRefTyped("ModifiedProperties", json::Json::Type::Object))),
        MapT(argsWithMode(makeValue(R"("raw_keys")")),
             opBuilderHelperArrayExtractKeyObj,
             SUCCESS(builderArrayRefTyped("ModifiedProperties", json::Json::Type::Object))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefTyped("ModifiedProperties", json::Json::Type::String))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefTyped("ModifiedProperties", json::Json::Type::Number))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefTyped("ModifiedProperties", json::Json::Type::Boolean))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefTyped("ModifiedProperties", json::Json::Type::Array))),
        MapT(defaultArgs(),
             opBuilderHelperArrayExtractKeyObj,
             FAILURE(builderArrayRefTyped("ModifiedProperties", json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("ArrayExtractKeyObj"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayExtractKeyObj,
    MapOperationTest,
    testing::Values(
        // Keys are normalized to lowercase snake_case by default, a blank old value is dropped
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data", "OldValue": "old-data"},
                        {"Name": "Included Updated Properties", "NewValue": "RequiredResourceAccess", "OldValue": ""}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": {"NewValue": "new-data", "OldValue": "old-data"},
                    "included_updated_properties": {"NewValue": "RequiredResourceAccess"}
                })")))),
        // 'raw_keys' keeps the keys verbatim
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data", "OldValue": "old-data"},
                        {"Name": "Included Updated Properties", "NewValue": "RequiredResourceAccess", "OldValue": ""}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            argsWithMode(makeValue(R"("raw_keys")")),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "RequiredResourceAccess": {"NewValue": "new-data", "OldValue": "old-data"},
                    "Included Updated Properties": {"NewValue": "RequiredResourceAccess"}
                })")))),
        // 'raw_keys' with characters that are special in a JSON pointer; a null old value is kept
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "SCL/Reject", "NewValue": "value1", "OldValue": "previous"},
                        {"Name": "tilde~value", "NewValue": "value2", "OldValue": null},
                        {"Name": "weird~slash/tilde.name", "NewValue": "value3", "OldValue": ""}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            argsWithMode(makeValue(R"("raw_keys")")),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "SCL/Reject": {"NewValue": "value1", "OldValue": "previous"},
                    "tilde~value": {"NewValue": "value2", "OldValue": null},
                    "weird~slash/tilde.name": {"NewValue": "value3"}
                })")))),
        // Missing old value
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data"}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": {"NewValue": "new-data"}
                })")))),
        // A whitespace-only old value is dropped
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "FeatureFlag", "NewValue": true, "OldValue": "   "}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "featureflag": {"NewValue": true}
                })")))),
        // Non-string values are kept as they are
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "Count", "NewValue": 2, "OldValue": 1},
                        {"Name": "Tags", "NewValue": ["a", "b"], "OldValue": {"x": 1}}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "count": {"NewValue": 2, "OldValue": 1},
                    "tags": {"NewValue": ["a", "b"], "OldValue": {"x": 1}}
                })")))),
        // Nested dot paths, relative to each element: the whole relative path is kept under the key
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "Role", "changes": {"new": "admin", "old": "user"}}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            {makeRef("ModifiedProperties"),
             makeValue(R"("Name")"),
             makeValue(R"("changes.new")"),
             makeValue(R"("changes.old")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "role": {"changes": {"new": "admin", "old": "user"}}
                })")))),
        // An element without the new value is skipped
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "OldValue": "old-data"}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
        // The key must be a non-empty string
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "", "NewValue": "new-data", "OldValue": "old-data"},
                        {"Name": 5, "NewValue": "new-data", "OldValue": "old-data"},
                        {"NewValue": "new-data", "OldValue": "old-data"}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
        // Elements that are not objects are skipped
        MapT(
            R"({
                    "ModifiedProperties": [
                        "Only Flag",
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data", "OldValue": "old-data"}
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": {"NewValue": "new-data", "OldValue": "old-data"}
                })")))),
        MapT(
            R"({
                    "ModifiedProperties": [
                        "Only Flag"
                    ]
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
        // Array reference not found or not an array
        MapT("{}",
             opBuilderHelperArrayExtractKeyObj,
             defaultArgs(),
             FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
        MapT(
            R"({
                    "ModifiedProperties": {"Name": "not-an-array"}
                })",
            opBuilderHelperArrayExtractKeyObj,
            defaultArgs(),
            FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties")))),
    testNameFormatter<MapOperationTest>("ArrayExtractKeyObj"));
} // namespace mapoperatestest

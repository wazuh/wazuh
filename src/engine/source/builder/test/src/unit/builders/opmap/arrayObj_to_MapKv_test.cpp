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

} // namespace

// array_to_object($array, 'key_path', 'value_path', ['raw_keys'])
// The key and value paths are dot paths relative to each element of the array ('.' is the whole element).
namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayObjToMapKv,
    MapBuilderTest,
    testing::Values(
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("meta.name")"), makeValue(R"("data.value")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"(".")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefNotInSchema("ExtendedProperties"))),
        // A JSON pointer (leading '/') is rejected: paths are dot paths
        MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("/Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        /*** Arity ***/
        MapT({}, opBuilderHelperArrayObjToMapkv, FAILURE()),
        MapT({makeRef("ExtendedProperties")}, opBuilderHelperArrayObjToMapkv, FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")")}, opBuilderHelperArrayObjToMapkv, FAILURE()),
        MapT({makeRef("ExtendedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("Value")"),
              makeValue(R"("raw_keys")"),
              makeValue(R"("raw_keys")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        /*** Argument kinds and types ***/
        MapT({makeValue(R"("ExtendedProperties")"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeRef("Name"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeRef("Value")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"(1)"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"(1)")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        /*** Optional mode: only the literal 'raw_keys' is accepted ***/
        MapT({makeRef("ExtendedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("Value")"),
              makeValue(R"("raw_keys")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefNotInSchema("ExtendedProperties"))),
        // The old boolean flag is a build error
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")"), makeValue(R"(true)")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")"), makeValue(R"(false)")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")"), makeValue(R"("skip")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("Value")"),
              makeValue(R"("RAW_KEYS")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")"), makeValue(R"("")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")"), makeValue(R"(1)")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")"), makeRef("raw_keys")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
        /*** Array ref type validation (getJsonType -> Object) ***/
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefNotArray("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefWrongElement("ExtendedProperties"))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefTyped("ExtendedProperties", json::Json::Type::Object))),
        MapT({makeRef("ExtendedProperties"),
              makeValue(R"("Name")"),
              makeValue(R"("Value")"),
              makeValue(R"("raw_keys")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefTyped("ExtendedProperties", json::Json::Type::Object))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefTyped("ExtendedProperties", json::Json::Type::String))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefTyped("ExtendedProperties", json::Json::Type::Number))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefTyped("ExtendedProperties", json::Json::Type::Boolean))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefTyped("ExtendedProperties", json::Json::Type::Array))),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE(builderArrayRefTyped("ExtendedProperties", json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("ArrayObjToMapKv"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayObjToMapKv,
    MapOperationTest,
    testing::Values(
        // Keys are normalized to lowercase snake_case by default
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "UserAgent", "Value": "Mozilla/5.0"},
                        {"Name": "Age", "Value": 42},
                        {"Name": "KeepMeSignedIn", "Value": true},
                        {"Name": "OptionalField", "Value": null},
                        {"Name": "Roles", "Value": ["admin", "user"]},
                        {"Name": "Meta", "Value": {"os": "linux", "arch": "x64"}}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "useragent": "Mozilla/5.0",
                    "age": 42,
                    "keepmesignedin": true,
                    "optionalfield": null,
                    "roles": ["admin", "user"],
                    "meta": {"os": "linux", "arch": "x64"}
                })")))),
        // 'raw_keys' keeps the keys verbatim
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "UserAgent", "Value": "Mozilla/5.0"},
                        {"Name": "Age", "Value": 42},
                        {"Name": "KeepMeSignedIn", "Value": true},
                        {"Name": "OptionalField", "Value": null},
                        {"Name": "Roles", "Value": ["admin", "user"]},
                        {"Name": "Meta", "Value": {"os": "linux", "arch": "x64"}}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"),
             makeValue(R"("Name")"),
             makeValue(R"("Value")"),
             makeValue(R"("raw_keys")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "UserAgent": "Mozilla/5.0",
                    "Age": 42,
                    "KeepMeSignedIn": true,
                    "OptionalField": null,
                    "Roles": ["admin", "user"],
                    "Meta": {"os": "linux", "arch": "x64"}
                })")))),
        // 'raw_keys' with characters that are special in a JSON pointer
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "SCL/Reject", "Value": "value1"},
                        {"Name": "tilde~value", "Value": "value2"},
                        {"Name": "weird~slash/tilde.name", "Value": "value3"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"),
             makeValue(R"("Name")"),
             makeValue(R"("Value")"),
             makeValue(R"("raw_keys")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "SCL/Reject": "value1",
                    "tilde~value": "value2",
                    "weird~slash/tilde.name": "value3"
                })")))),
        // Separators become underscores, other non-alphanumeric characters are dropped
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "UserAgent", "Value": "Mozilla/5.0"},
                        {"Name": "Request.Type", "Value": "OAuth2:Authorize"},
                        {"Name": "Included Updated Properties", "Value": "RequiredResourceAccess"},
                        {"Name": "tilde~value", "Value": "data"},
                        {"Name": "SCL/Reject", "Value": "False"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "useragent": "Mozilla/5.0",
                    "request_type": "OAuth2:Authorize",
                    "included_updated_properties": "RequiredResourceAccess",
                    "tildevalue": "data",
                    "scl_reject": "False"
                })")))),
        // Already normalized keys are kept, leading and trailing underscores are dropped
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "already_snake", "Value": "value1"},
                        {"Name": "SCL_Reject", "Value": "value2"},
                        {"Name": "__meta__", "Value": "value3"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "already_snake": "value1",
                    "scl_reject": "value2",
                    "meta": "value3"
                })")))),
        // Any member can be the value
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data"},
                        {"Name": "Included Updated Properties", "NewValue": "RequiredResourceAccess"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("NewValue")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": "new-data",
                    "included_updated_properties": "RequiredResourceAccess"
                })")))),
        // Nested dot paths, relative to each element
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"meta": {"name": "Host Name"}, "data": {"value": "srv1"}},
                        {"meta": {"name": "Port"}, "data": {"value": 22}}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("meta.name")"), makeValue(R"("data.value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "host_name": "srv1",
                    "port": 22
                })")))),
        // '.' as the value path maps the whole element
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "Alpha", "Value": 1}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"(".")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "alpha": {"Name": "Alpha", "Value": 1}
                })")))),
        // Elements that are not objects are skipped
        MapT(
            R"({
                    "Parameters": [
                        "Only Flag",
                        {"Name": "Other", "Value": "42"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("Parameters"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("Parameters", json::Json(R"({
                    "other": "42"
                })")))),
        // Nothing mapped -> failure
        MapT(
            R"({
                    "Parameters": [
                        "Only Flag"
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("Parameters"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("Parameters"))),
        // Empty key, missing value and missing key are skipped
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "", "Value": "empty"},
                        {"Name": "MissingValue"},
                        {"Other": "value"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ModifiedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
        // The key must be a string: '.' (the whole element) and a number are skipped
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "Alpha", "Value": 1}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"(".")"), makeValue(R"("Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ExtendedProperties"))),
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": 5, "Value": "x"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ExtendedProperties"))),
        // A key that normalizes to an empty string is skipped, 'raw_keys' keeps it
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "~~", "Value": "x"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ExtendedProperties"))),
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "~~", "Value": "x"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"),
             makeValue(R"("Name")"),
             makeValue(R"("Value")"),
             makeValue(R"("raw_keys")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "~~": "x"
                })")))),
        // Array reference not found or not an array
        MapT("{}",
             opBuilderHelperArrayObjToMapkv,
             {makeRef("Parameters"), makeValue(R"("Name")"), makeValue(R"("Value")")},
             FAILURE(opArrayRefNotInSchemaFailure("Parameters"))),
        MapT(
            R"({
                    "ExtendedProperties": {"Name": "not-an-array"}
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ExtendedProperties")))),
    testNameFormatter<MapOperationTest>("ArrayObjToMapKv"));
} // namespace mapoperatestest

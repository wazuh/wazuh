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
        EXPECT_CALL(*mocks.validator, isArray(DotPath(refName))).WillRepeatedly(testing::Return(false));
        return None {};
    };
}

auto builderArrayRefWrongElement(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        expectValidatorAccess(mocks);
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillRepeatedly(testing::Return(true));
        EXPECT_CALL(*mocks.validator, isArray(DotPath(refName))).WillRepeatedly(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(refName)))
            .WillRepeatedly(testing::Return(json::Json::Type::String));
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
        EXPECT_CALL(*mocks.validator, isArray(DotPath(refName))).WillRepeatedly(testing::Return(false));
        return None {};
    };
}

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayObjToMapKv,
    MapBuilderTest,
    testing::Values(MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         SUCCESS(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({}, opBuilderHelperArrayObjToMapkv, FAILURE()),
                    MapT({makeValue(R"("ExtendedProperties")"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE()),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"(1)"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"(1)")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("")"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotInSchema("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefNotArray("ExtendedProperties"))),
                    MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
                         opBuilderHelperArrayObjToMapkv,
                         FAILURE(builderArrayRefWrongElement("ExtendedProperties")))),
    testNameFormatter<MapBuilderTest>("ArrayObjToMapKv"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayObjToMapKv,
    MapOperationTest,
    testing::Values(
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
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "useragent": "Mozilla/5.0",
                    "age": 42,
                    "keepmesignedin": true,
                    "optionalfield": null,
                    "roles": ["admin", "user"],
                    "meta": {"os": "linux", "arch": "x64"}
                })")))),
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
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")"), makeValue(R"(true)")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "UserAgent": "Mozilla/5.0",
                    "Age": 42,
                    "KeepMeSignedIn": true,
                    "OptionalField": null,
                    "Roles": ["admin", "user"],
                    "Meta": {"os": "linux", "arch": "x64"}
                })")))),
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "SCL/Reject", "Value": "value1"},
                        {"Name": "tilde~value", "Value": "value2"},
                        {"Name": "weird~slash/tilde.name", "Value": "value3"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")"), makeValue(R"(true)")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "SCL/Reject": "value1",
                    "tilde~value": "value2",
                    "weird~slash/tilde.name": "value3"
                })")))),
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
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "useragent": "Mozilla/5.0",
                    "request_type": "OAuth2:Authorize",
                    "included_updated_properties": "RequiredResourceAccess",
                    "tildevalue": "data",
                    "scl_reject": "False"
                })")))),
        MapT(
            R"({
                    "ExtendedProperties": [
                        {"Name": "already_snake", "Value": "value1"},
                        {"Name": "SCL_Reject", "Value": "value2"},
                        {"Name": "__meta__", "Value": "value3"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ExtendedProperties", json::Json(R"({
                    "already_snake": "value1",
                    "scl_reject": "value2",
                    "meta": "value3"
                })")))),
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data"},
                        {"Name": "Included Updated Properties", "NewValue": "RequiredResourceAccess"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ModifiedProperties"), makeValue(R"("/Name")"), makeValue(R"("/NewValue")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": "new-data",
                    "included_updated_properties": "RequiredResourceAccess"
                })")))),
        MapT(
            R"({
                    "Parameters": [
                        "Only Flag",
                        {"Name": "Other", "Value": "42"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("Parameters"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess("Parameters", json::Json(R"({
                    "other": "42"
                })")))),
        MapT(
            R"({
                    "Parameters": [
                        "Only Flag"
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("Parameters"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("Parameters"))),
        MapT(
            R"({
                    "ModifiedProperties": [
                        {"Name": "", "Value": "empty"},
                        {"Name": "MissingValue"},
                        {"Other": "value"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ModifiedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
        MapT("{}",
             opBuilderHelperArrayObjToMapkv,
             {makeRef("Parameters"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
             FAILURE(opArrayRefNotInSchemaFailure("Parameters"))),
        MapT(
            R"({
                    "ExtendedProperties": {"Name": "not-an-array"}
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            FAILURE(opArrayRefNotInSchemaFailure("ExtendedProperties")))),
    testNameFormatter<MapOperationTest>("ArrayObjToMapKv"));
} // namespace mapoperatestest

#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
auto builderArrayRefNotInSchema(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto builderArrayRefNotArray(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, isArray(DotPath(refName))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto builderArrayRefWrongElement(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, isArray(DotPath(refName))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(refName))).WillOnce(testing::Return(json::Json::Type::String));
        return None {};
    };
}

auto opArrayRefNotInSchemaSuccess(const std::string& refName, const json::Json& expectedJson)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(false));
        return expectedJson;
    };
}

auto opArrayRefNotInSchemaFailure(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto opArrayRefNotArray(const std::string& refName)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, isArray(DotPath(refName))).WillOnce(testing::Return(false));
        return None {};
    };
}

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    ArrayObjToMapKv,
    MapBuilderTest,
    testing::Values(
        MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
             opBuilderHelperArrayObjToMapkv,
             SUCCESS(builderArrayRefNotInSchema("ExtendedProperties"))),
        MapT({}, opBuilderHelperArrayObjToMapkv, FAILURE()),
        MapT({makeValue(R"("ExtendedProperties")"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"(1)"), makeValue(R"("/Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"(1)")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("")"), makeValue(R"("/Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("Name")"), makeValue(R"("/Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
        MapT({makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("Value")")},
             opBuilderHelperArrayObjToMapkv,
             FAILURE()),
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
                        {"Name": "Request.Type", "Value": "OAuth2:Authorize"},
                        {"Name": "Included Updated Properties", "Value": "RequiredResourceAccess"},
                        {"Name": "tilde~value", "Value": "data"},
                        {"Name": "SCL/Reject", "Value": "False"}
                    ]
                })",
            opBuilderHelperArrayObjToMapkv,
            {makeRef("ExtendedProperties"), makeValue(R"("/Name")"), makeValue(R"("/Value")")},
            SUCCESS(opArrayRefNotInSchemaSuccess(
                "ExtendedProperties",
                json::Json(R"({
                    "UserAgent": "Mozilla/5.0",
                    "Request_Type": "OAuth2:Authorize",
                    "Included_Updated_Properties": "RequiredResourceAccess",
                    "tilde_value": "data",
                    "SCL_Reject": "False"
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
            SUCCESS(opArrayRefNotInSchemaSuccess(
                "ModifiedProperties",
                json::Json(R"({
                    "RequiredResourceAccess": { "NewValue": "new-data" },
                    "Included_Updated_Properties": { "NewValue": "RequiredResourceAccess" }
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
            SUCCESS(opArrayRefNotInSchemaSuccess(
                "Parameters",
                json::Json(R"({
                    "Other": { "Value": "42" }
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
            FAILURE(opArrayRefNotArray("ExtendedProperties")))),
    testNameFormatter<MapOperationTest>("ArrayObjToMapKv"));
} // namespace mapoperatestest

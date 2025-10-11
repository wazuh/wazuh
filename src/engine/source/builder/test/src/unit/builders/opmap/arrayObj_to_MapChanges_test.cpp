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
    ArrayObjToMapChanges,
    MapBuilderTest,
    testing::Values(
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("/Name")"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             SUCCESS(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({}, opBuilderHelperArrayObjToMapChanges, FAILURE()),
        MapT({makeValue(R"("ModifiedProperties")"),
              makeValue(R"("/Name")"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE()),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"(1)"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("/Name")"), makeValue(R"(1)"), makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("/Name")"), makeValue(R"("/NewValue")"), makeValue(R"(1)")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("")"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("/Name")"), makeValue(R"("")"), makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"), makeValue(R"("/Name")"), makeValue(R"("/NewValue")"), makeValue(R"("")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotInSchema("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("/Name")"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefNotArray("ModifiedProperties"))),
        MapT({makeRef("ModifiedProperties"),
              makeValue(R"("/Name")"),
              makeValue(R"("/NewValue")"),
              makeValue(R"("/OldValue")")},
             opBuilderHelperArrayObjToMapChanges,
             FAILURE(builderArrayRefWrongElement("ModifiedProperties")))),
    testNameFormatter<MapBuilderTest>("ArrayObjToMapChanges"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(ArrayObjToMapChanges,
                         MapOperationTest,
                         testing::Values(MapT(
                                             R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data", "OldValue": "old-data"},
                        {"Name": "Included Updated Properties", "NewValue": "RequiredResourceAccess", "OldValue": ""}
                    ]
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")")},
                                             SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": {"NewValue": "new-data", "OldValue": "old-data"},
                    "included_updated_properties": {"NewValue": "RequiredResourceAccess"}
                })")))),
                                         MapT(
                                             R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data", "OldValue": "old-data"},
                        {"Name": "Included Updated Properties", "NewValue": "RequiredResourceAccess", "OldValue": ""}
                    ]
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")"),
                                              makeValue(R"(true)")},
                                             SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "RequiredResourceAccess": {"NewValue": "new-data", "OldValue": "old-data"},
                    "Included Updated Properties": {"NewValue": "RequiredResourceAccess"}
                })")))),
                                         MapT(
                                             R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "NewValue": "new-data"}
                    ]
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")")},
                                             SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "requiredresourceaccess": {"NewValue": "new-data"}
                })")))),
                                         MapT(
                                             R"({
                    "ModifiedProperties": [
                        {"Name": "FeatureFlag", "NewValue": true, "OldValue": "   "}
                    ]
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")")},
                                             SUCCESS(opArrayRefNotInSchemaSuccess("ModifiedProperties", json::Json(R"({
                    "featureflag": {"NewValue": true}
                })")))),
                                         MapT(
                                             R"({
                    "ModifiedProperties": [
                        {"Name": "RequiredResourceAccess", "OldValue": "old-data"}
                    ]
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")")},
                                             FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
                                         MapT(
                                             R"({
                    "ModifiedProperties": [
                        "Only Flag"
                    ]
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")")},
                                             FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
                                         MapT("{}",
                                              opBuilderHelperArrayObjToMapChanges,
                                              {makeRef("ModifiedProperties"),
                                               makeValue(R"("/Name")"),
                                               makeValue(R"("/NewValue")"),
                                               makeValue(R"("/OldValue")")},
                                              FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties"))),
                                         MapT(
                                             R"({
                    "ModifiedProperties": {"Name": "not-an-array"}
                })",
                                             opBuilderHelperArrayObjToMapChanges,
                                             {makeRef("ModifiedProperties"),
                                              makeValue(R"("/Name")"),
                                              makeValue(R"("/NewValue")"),
                                              makeValue(R"("/OldValue")")},
                                             FAILURE(opArrayRefNotInSchemaFailure("ModifiedProperties")))),
                         testNameFormatter<MapOperationTest>("ArrayObjToMapChanges"));
} // namespace mapoperatestest

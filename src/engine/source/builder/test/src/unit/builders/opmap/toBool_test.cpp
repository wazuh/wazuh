#include "builders/baseBuilders_test.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
    auto customRefExpected(bool times = false)
    {
        return [=](const BuildersMocks& mocks)
        {
            if (times)
            {
                EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
                EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(false));
            }
            else
            {
                EXPECT_CALL(*mocks.ctx, validator());
                EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
            }
            return None {};
        };
    }

    auto customRefExpected(json::Json jValue)
    {
        return [=](const BuildersMocks& mocks)
        {
            EXPECT_CALL(*mocks.ctx, validator());
            EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
            return jValue;
        };
    }

    auto schemaRefExpected(schemf::Type sType)
    {
        return [=](const BuildersMocks& mocks)
        {
            EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
            EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
            EXPECT_CALL(*mocks.validator, getType(DotPath("ref"))).WillOnce(testing::Return(sType));
            return None {};
        };
    }
}

namespace mapbuildtest
{
    INSTANTIATE_TEST_SUITE_P(
        Builders,
        MapBuilderTest,
        testing::Values(
            MapT({}, opBuilderHelperToBoolStr, FAILURE()),
            MapT({makeValue(R"("true")")}, opBuilderHelperToBoolStr, FAILURE()),
            MapT({makeRef("ref")}, opBuilderHelperToBoolStr, SUCCESS()),
            MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperToBoolStr, FAILURE())),
        testNameFormatter<MapBuilderTest>("ToBool"));
}

namespace mapoperatestest
{
    INSTANTIATE_TEST_SUITE_P(
        Builders,
        MapOperationTest,
        testing::Values(
            /*** to_bool ***/
            /*** invalid type reference field ***/
            MapT(R"({"ref": "some"})", opBuilderHelperToBoolStr, {makeRef("ref")}, FAILURE(customRefExpected())),
            MapT(R"({"ref": "[1,2,3,4]"})", opBuilderHelperToBoolStr, {makeRef("ref")}, FAILURE(customRefExpected())),
            MapT(R"({"ref": {"key": "value"}})", opBuilderHelperToBoolStr, {makeRef("ref")}, FAILURE(customRefExpected())),
            /*** success cases ***/
            MapT(R"({"ref": 1})", opBuilderHelperToBoolStr, {makeRef("ref")},
                SUCCESS(customRefExpected(json::Json(R"("true")")))),
            MapT(R"({"ref": 1.0})", opBuilderHelperToBoolStr, {makeRef("ref")},
                SUCCESS(customRefExpected(json::Json(R"("true")")))),
            MapT(R"({"ref": 0})", opBuilderHelperToBoolStr, {makeRef("ref")},
                SUCCESS(customRefExpected(json::Json(R"("false")")))),
            MapT(R"({"ref": 0.0})", opBuilderHelperToBoolStr, {makeRef("ref")},
                SUCCESS(customRefExpected(json::Json(R"("false")")))),
            /*** unsupported numeric values -> failure ***/
            MapT(R"({"ref": 2})", opBuilderHelperToBoolStr, {makeRef("ref")}, FAILURE(customRefExpected())),
            MapT(R"({"ref": -1})", opBuilderHelperToBoolStr, {makeRef("ref")}, FAILURE(customRefExpected())),
            MapT(R"({"ref": 0.5})", opBuilderHelperToBoolStr, {makeRef("ref")}, FAILURE(customRefExpected()))),
        testNameFormatter<MapOperationTest>("ToBool"));
}


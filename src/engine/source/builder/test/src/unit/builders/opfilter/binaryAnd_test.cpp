#include "builders/baseBuilders_test.hpp"
#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{
auto customRefExpected = [](const std::string& refName = "ref")
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, isTestMode()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.ctx, validator());
        return None {};
    };
};

auto typeRefExpected = [](json::Json::Type type, bool success = true, const std::string& refName = "ref")
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, isTestMode()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(refName))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(refName))).WillRepeatedly(testing::Return(type));
        return None {};
    };
};
} // namespace

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        // Wrong number of arguments
        FilterT({}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0x1")"), makeValue(R"("0x2")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // Value cases
        FilterT({makeValue(R"(1)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("nothex")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0x")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0x0")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE())),
    testNameFormatter<FilterBuilderTest>("BinaryAnd"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        // Value cases
        FilterT(R"({"target": "0xF0"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0xF0")")},
                SUCCESS()),
        FilterT(R"({"target": "0x0F"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0xF0")")},
                FAILURE()),
        FilterT(R"({"target": "0xFF"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0xF0")")},
                SUCCESS()),
        FilterT(R"({"target": "0x00"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0xF0")")},
                FAILURE()),
        FilterT(R"({"target": "0x10"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x10")")},
                SUCCESS()),
        FilterT(R"({"target": "0x20"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x10")")},
                FAILURE()),
        // Missing target field
        FilterT(R"({"othe(R": "0x10"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x10")")},
                FAILURE())),
    testNameFormatter<FilterOperationTest>("BinaryAnd"));
} // namespace filteroperatestest

#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        /*** Array Length ***/
        FilterT({}, opfilter::opBuilderHelperArrayLength, FAILURE()),
        FilterT({makeValue(R"(1)")}, opfilter::opBuilderHelperArrayLength, SUCCESS()),
        FilterT({makeValue(R"(0)")}, opfilter::opBuilderHelperArrayLength, SUCCESS()),
        FilterT({makeValue(R"(5)")}, opfilter::opBuilderHelperArrayLength, SUCCESS()),
        FilterT({makeValue(R"(-1)")}, opfilter::opBuilderHelperArrayLength, FAILURE()),
        FilterT({makeValue(R"("not_a_number")")}, opfilter::opBuilderHelperArrayLength, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperArrayLength, FAILURE()),
        FilterT({makeValue(R"(1)"), makeValue(R"(2)")}, opfilter::opBuilderHelperArrayLength, FAILURE())),
    testNameFormatter<FilterBuilderTest>("ArrayLength"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        /*** Array Length ***/
        // Test with array of length 1
        FilterT(
            R"({"target": ["value"]})", opfilter::opBuilderHelperArrayLength, "target", {makeValue(R"(1)")}, SUCCESS()),
        // Test with array of length 3
        FilterT(R"({"target": ["v1", "v2", "v3"]})",
                opfilter::opBuilderHelperArrayLength,
                "target",
                {makeValue(R"(3)")},
                SUCCESS()),
        // Test with empty array
        FilterT(R"({"target": []})", opfilter::opBuilderHelperArrayLength, "target", {makeValue(R"(0)")}, SUCCESS()),
        // Test with wrong length
        FilterT(R"({"target": ["v1", "v2"]})",
                opfilter::opBuilderHelperArrayLength,
                "target",
                {makeValue(R"(1)")},
                FAILURE()),
        // Test with non-existent field
        FilterT(R"({"other": []})", opfilter::opBuilderHelperArrayLength, "target", {makeValue(R"(0)")}, FAILURE()),
        // Test with non-array field
        FilterT(
            R"({"target": "string"})", opfilter::opBuilderHelperArrayLength, "target", {makeValue(R"(1)")}, FAILURE()),
        // Test with numeric array
        FilterT(R"({"target": [1, 2, 3, 4, 5]})",
                opfilter::opBuilderHelperArrayLength,
                "target",
                {makeValue(R"(5)")},
                SUCCESS())),
    testNameFormatter<FilterOperationTest>("ArrayLength"));
} // namespace filteroperatestest

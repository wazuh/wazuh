#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{

auto contextExpected(bool indexUnclassified)
{
    return [=](const BuildersMocks& mocks)
    {
        static Context ctx;
        ctx.assetName = "test/asset";
        ctx.policyName = "test/policy";
        ctx.indexUnclassifiedEvents = indexUnclassified;

        ON_CALL(*mocks.ctx, context()).WillByDefault(testing::ReturnRef(ctx));

        return None {};
    };
}

} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterBuilderTest,
                         testing::Values(
                             /*** Index Unclassified Events ***/
                             FilterT({}, opfilter::opBuilderHelperIndexUnclassifiedEvents, SUCCESS()),
                             FilterT({makeValue(R"(1)")}, opfilter::opBuilderHelperIndexUnclassifiedEvents, FAILURE()),
                             FilterT({makeRef("ref")}, opfilter::opBuilderHelperIndexUnclassifiedEvents, FAILURE())),
                         testNameFormatter<FilterBuilderTest>("IndexUnclassifiedEvents"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterOperationTest,
                         testing::Values(
                             /*** Index Unclassified Events - Tests with policy disabled (default) ***/
                             // Policy disabled, array size 1 - should fail
                             FilterT(R"({"target": ["decoder1"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(false))),
                             // Policy disabled, array size 2 - should fail
                             FilterT(R"({"target": ["decoder1", "decoder2"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(false))),
                             // Policy disabled, empty array - should fail
                             FilterT(R"({"target": []})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(false))),
                             /*** Index Unclassified Events - Tests with policy enabled ***/
                             // Policy enabled, array size 1 - should succeed
                             FilterT(R"({"target": ["decoder1"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     SUCCESS(contextExpected(true))),
                             // Policy enabled, array size 2 - should fail
                             FilterT(R"({"target": ["decoder1", "decoder2"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(true))),
                             // Policy enabled, empty array - should fail
                             FilterT(R"({"target": []})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(true))),
                             // Policy enabled, array size 3 - should fail
                             FilterT(R"({"target": ["d1", "d2", "d3"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(true))),
                             /*** Index Unclassified Events - Error cases ***/
                             // Test with non-existent field (policy enabled)
                             FilterT(R"({"other": ["decoder"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(true))),
                             // Test with non-array field (policy enabled)
                             FilterT(R"({"target": "decoder"})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "target",
                                     {},
                                     FAILURE(contextExpected(true)))),
                         testNameFormatter<FilterOperationTest>("IndexUnclassifiedEvents"));
} // namespace filteroperatestest

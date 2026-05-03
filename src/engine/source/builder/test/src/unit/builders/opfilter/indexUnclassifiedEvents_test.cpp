#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"
#include "syntax.hpp"

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
class IndexUnclassifiedEventsBuildTest : public BaseBuilderTest
{
};

TEST_F(IndexUnclassifiedEventsBuildTest, BuildsWithDecodersField)
{
    Reference targetField {"wazuh.integration.decoders"};

    contextExpected(true)(*mocks);
    expectBuildSuccess();

    ASSERT_NO_THROW(opfilter::opBuilderHelperIndexUnclassifiedEvents(targetField, {}, mocks->ctx));
}

TEST_F(IndexUnclassifiedEventsBuildTest, RejectsUnexpectedTargetField)
{
    Reference targetField {"targetField"};

    ASSERT_THROW(opfilter::opBuilderHelperIndexUnclassifiedEvents(targetField, {}, mocks->ctx), std::exception);
}

TEST_F(IndexUnclassifiedEventsBuildTest, RejectsValueArgument)
{
    Reference targetField {"wazuh.integration.decoders"};

    ASSERT_THROW(opfilter::opBuilderHelperIndexUnclassifiedEvents(targetField, {makeValue(R"(1)")}, mocks->ctx),
                 std::exception);
}

TEST_F(IndexUnclassifiedEventsBuildTest, RejectsReferenceArgument)
{
    Reference targetField {"wazuh.integration.decoders"};

    ASSERT_THROW(opfilter::opBuilderHelperIndexUnclassifiedEvents(targetField, {makeRef("ref")}, mocks->ctx),
                 std::exception);
}
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterOperationTest,
                         testing::Values(
                             /*** Index Unclassified Events - Tests with policy disabled (default) ***/
                             // Policy disabled, array size 1 - should fail
                             FilterT(R"({"wazuh": {"integration": {"decoders": ["decoder1"]}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(false))),
                             // Policy disabled, array size 2 - should fail
                             FilterT(R"({"wazuh": {"integration": {"decoders": ["decoder1", "decoder2"]}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(false))),
                             // Policy disabled, empty array - should fail
                             FilterT(R"({"wazuh": {"integration": {"decoders": []}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(false))),
                             /*** Index Unclassified Events - Tests with policy enabled ***/
                             // Policy enabled, array size 1 - should succeed
                             FilterT(R"({"wazuh": {"integration": {"decoders": ["decoder1"]}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     SUCCESS(contextExpected(true))),
                             // Policy enabled, array size 2 - should fail
                             FilterT(R"({"wazuh": {"integration": {"decoders": ["decoder1", "decoder2"]}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(true))),
                             // Policy enabled, empty array - should fail
                             FilterT(R"({"wazuh": {"integration": {"decoders": []}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(true))),
                             // Policy enabled, array size 3 - should fail
                             FilterT(R"({"wazuh": {"integration": {"decoders": ["d1", "d2", "d3"]}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(true))),
                             /*** Index Unclassified Events - Error cases ***/
                             // Test with non-existent field (policy enabled)
                             FilterT(R"({"other": ["decoder"]})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(true))),
                             // Test with non-array field (policy enabled)
                             FilterT(R"({"wazuh": {"integration": {"decoders": "decoder"}}})",
                                     opfilter::opBuilderHelperIndexUnclassifiedEvents,
                                     "wazuh.integration.decoders",
                                     {},
                                     FAILURE(contextExpected(true)))),
                         testNameFormatter<FilterOperationTest>("IndexUnclassifiedEvents"));
} // namespace filteroperatestest

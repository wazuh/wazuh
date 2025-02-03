#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{

auto runStateExpected(bool trace, bool sandbox)
{
    return [=](const BuildersMocks& mocks)
    {
        mocks.runState->sandbox = sandbox;
        mocks.runState->trace = trace;
        return None {};
    };
}

} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(BuilderIsSessionTest,
                         FilterBuilderTest,
                         testing::Values(
                             // Wrong arguments number
                             FilterT({makeValue()}, opfilter::opBuilderHelperIsTestSession, FAILURE()),
                             FilterT({makeValue()}, opfilter::opBuilderHelperIsTestSession, FAILURE()),
                             FilterT({makeRef()}, opfilter::opBuilderHelperIsTestSession, FAILURE()),
                             FilterT({makeRef()}, opfilter::opBuilderHelperIsTestSession, FAILURE()),
                             // Success case
                             FilterT({}, opfilter::opBuilderHelperIsTestSession, SUCCESS())),
                         testNameFormatter<FilterBuilderTest>("IsSessionTest"));
} // namespace filterbuildtest

namespace filteroperatestest
{

INSTANTIATE_TEST_SUITE_P(BuilderIsSessionTest,
                         FilterOperationTest,
                         testing::Values(FilterT(R"({"target": 1})",
                                                 opfilter::opBuilderHelperIsTestSession,
                                                 "target",
                                                 {},
                                                 FAILURE(runStateExpected(false, false))),
                                         FilterT(R"({"target": 1})",
                                                 opfilter::opBuilderHelperIsTestSession,
                                                 "target",
                                                 {},
                                                 SUCCESS(runStateExpected(true, true)))),
                         testNameFormatter<FilterOperationTest>("IsSessionTest"));
} // namespace filteroperatestest

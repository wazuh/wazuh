#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    BuilderIsIPv4,
    FilterBuilderTest,
    testing::Values(
        FilterT({}, opfilter::opBuilderHelperIsIpv4, SUCCESS()),
        FilterT({makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIsIpv4, FAILURE()),
        FilterT({makeRef("ref"), makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIsIpv4, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIsIpv4, FAILURE())),
    testNameFormatter<FilterBuilderTest>("BuilderIsIPv4"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    BuilderIsIPv4,
    FilterOperationTest,
    testing::Values(
        // Invalid input
        FilterT(R"({"target": 123})", opfilter::opBuilderHelperIsIpv4, "target", {}, FAILURE()),
        FilterT(R"({"target": 1.23})", opfilter::opBuilderHelperIsIpv4, "target", {}, FAILURE()),
        FilterT(R"({"target": [1,2,3]})", opfilter::opBuilderHelperIsIpv4, "target", {}, FAILURE()),
        FilterT(R"({"target": "False"})", opfilter::opBuilderHelperIsIpv4, "target", {}, FAILURE()),
        // IPv6
        FilterT(R"({"target": "2001:4860:4860::8888"})", opfilter::opBuilderHelperIsIpv4, "target", {}, FAILURE()),
        FilterT(R"({"target": "2001:0db8:0000:0000:0000:8a2e:0370:7334"})",
                opfilter::opBuilderHelperIsIpv4,
                "target",
                {},
                FAILURE()),
        // Special IPs
        FilterT(R"({"target": "127.0.0.1"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS()),
        FilterT(R"({"target": "127.0.0.1"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS()),
        FilterT(R"({"target": "127.1.1.1"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS()),
        FilterT(R"({"target": "192.168.1.1"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS()),
        FilterT(R"({"target": "10.0.0.1"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS()),
        // Public IP
        FilterT(R"({"target": "8.8.8.8"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS()),
        FilterT(R"({"target": "1.1.1.1"})", opfilter::opBuilderHelperIsIpv4, "target", {}, SUCCESS())
        // End of test cases
        ),
    testNameFormatter<FilterOperationTest>("BuilderIsIPv4"));
} // namespace filteroperatestest

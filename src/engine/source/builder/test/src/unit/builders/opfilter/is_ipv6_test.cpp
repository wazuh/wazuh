#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    BuilderIsIPv6,
    FilterBuilderTest,
    testing::Values(
        FilterT({}, opfilter::opBuilderHelperIsIpv6, SUCCESS()),
        FilterT({makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIsIpv6, FAILURE()),
        FilterT({makeRef("ref"), makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIsIpv6, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIsIpv6, FAILURE())),
    testNameFormatter<FilterBuilderTest>("BuilderIsIPv6"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    BuilderIsIPv6,
    FilterOperationTest,
    testing::Values(
        // Invalid input
        FilterT(R"({"target": 123})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        FilterT(R"({"target": 12.3})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        FilterT(R"({"target": [1,2,3]})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        FilterT(R"({"target": "False"})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        // IPv4
        FilterT(R"({"target": "127.0.0.1"})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        FilterT(R"({"target": "8.8.8.8"})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        FilterT(R"({"target": "192.168.1.1"})", opfilter::opBuilderHelperIsIpv6, "target", {}, FAILURE()),
        // Special IPs
        FilterT(R"({"target": "::1"})", opfilter::opBuilderHelperIsIpv6, "target", {}, SUCCESS()),
        FilterT(R"({"target": "fd12:3456:789a::1"})", opfilter::opBuilderHelperIsIpv6, "target", {}, SUCCESS()),
        FilterT(R"({"target": "fd00:abcd::1234"})", opfilter::opBuilderHelperIsIpv6, "target", {}, SUCCESS()),
        // Public IP
        FilterT(R"({"target": "2001:0db8::1"})", opfilter::opBuilderHelperIsIpv6, "target", {}, SUCCESS()),
        FilterT(R"({"target": "2a03:2880:f10c:83:face:b00c::25de"})",
                opfilter::opBuilderHelperIsIpv6,
                "target",
                {},
                SUCCESS())
        // End of test cases
        ),
    testNameFormatter<FilterOperationTest>("BuilderIsIPv6"));
} // namespace filteroperatestest

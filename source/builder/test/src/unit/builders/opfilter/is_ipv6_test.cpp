#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    BuilderIsIPv6,
    FilterBuilderTest,
    testing::Values(FilterT({}, opfilter::opBuilderHelperIsIpv6, FAILURE()),
                    FilterT({makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIsIpv6, FAILURE()),
                    FilterT({makeRef("ref1"), makeRef("ref2")}, opfilter::opBuilderHelperIsIpv6, FAILURE()),
                    FilterT({makeRef("ref")}, opfilter::opBuilderHelperIsIpv6, SUCCESS())),
    testNameFormatter<FilterBuilderTest>("BuilderIsIPv6"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(BuilderIsIPv6,
                         FilterOperationTest,
                         testing::Values(
                             // Invalid input
                             FilterT(R"({"target": 123, "ref": 123})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             FilterT(R"({"target": 123, "ref": "1.23"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             FilterT(R"({"target": 123, "ref": [1,2,3]})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             FilterT(R"({"target": 123, "ref": "False"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             // IPv4
                             FilterT(R"({"target": "::1", "ref": "127.0.0.1"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             FilterT(R"({"target": "::1", "ref": "8.8.8.8"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             FilterT(R"({"target": "::1", "ref": "192.168.1.1"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     FAILURE()),
                             // Special IPs
                             FilterT(R"({"target": "::1", "ref": "::1"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     SUCCESS()),
                             FilterT(R"({"target": "::1", "ref": "fd12:3456:789a::1"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     SUCCESS()),
                             FilterT(R"({"target": "::1", "ref": "fd00:abcd::1234"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     SUCCESS()),
                             // Public IP
                             FilterT(R"({"target": "::1", "ref": "2001:0db8::1"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     SUCCESS()),
                             FilterT(R"({"target": "::1", "ref": "2a03:2880:f10c:83:face:b00c::25de"})",
                                     opfilter::opBuilderHelperIsIpv6,
                                     "target",
                                     {makeRef("ref")},
                                     SUCCESS())
                             // End of test cases
                             ),
                         testNameFormatter<FilterOperationTest>("BuilderIsIPv6"));
} // namespace filteroperatestest

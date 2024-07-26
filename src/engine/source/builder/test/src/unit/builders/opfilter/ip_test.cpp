#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    BuilderIPCIDR,
    FilterBuilderTest,
    testing::Values(
        FilterT({}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.255.255")"), makeValue(R"("24")")}, opfilter::opBuilderHelperIPCIDR, SUCCESS()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeRef("ref"), makeRef("ref")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeRef("ref"), makeValue(R"("24")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.255.255")"), makeRef("ref")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.255.0")"), makeValue(R"("255.255.255.0")")},
                opfilter::opBuilderHelperIPCIDR,
                SUCCESS())),
    testNameFormatter<FilterBuilderTest>("IPCIDR"));

INSTANTIATE_TEST_SUITE_P(
    BuilderPublicIP,
    FilterBuilderTest,
    testing::Values(FilterT({}, opfilter::opBuilderHelperPublicIP, SUCCESS()),
                    FilterT({makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperPublicIP, FAILURE()),
                    FilterT({makeRef("ref")}, opfilter::opBuilderHelperPublicIP, FAILURE())),
    testNameFormatter<FilterBuilderTest>("PublicIP"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(BuilderIPCIDR,
                         FilterOperationTest,
                         testing::Values(FilterT(R"({"target": "192.168.255.255/24"})",
                                                 opfilter::opBuilderHelperIPCIDR,
                                                 "target",
                                                 {makeValue(R"("192.168.255.0")"), makeValue(R"("24")")},
                                                 FAILURE()),
                                         FilterT(R"({"target": "192.168.255.255"})",
                                                 opfilter::opBuilderHelperIPCIDR,
                                                 "target",
                                                 {makeValue(R"("192.168.255.0")"), makeValue(R"("24")")},
                                                 SUCCESS()),
                                         FilterT(R"({"target": "192.168.255.255"})",
                                                 opfilter::opBuilderHelperIPCIDR,
                                                 "target",
                                                 {makeValue(R"("192.168.255.0")"), makeValue(R"("255.255.255.0")")},
                                                 SUCCESS()),
                                         FilterT(R"({"target": "192.168.255.255"})",
                                                 opfilter::opBuilderHelperIPCIDR,
                                                 "notTarget",
                                                 {makeValue(R"("192.168.255.0")"), makeValue(R"("255.255.255.0")")},
                                                 FAILURE())),
                         testNameFormatter<FilterOperationTest>("IPCIDR"));

INSTANTIATE_TEST_SUITE_P(
    BuilderPublicIP,
    FilterOperationTest,
    testing::Values(
        // Invalid input
        FilterT(R"({"notTarget": "8.8.8.8"})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": null})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": 123})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": 123.45})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": {"target": "::1"}})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        // Special IPs
        FilterT(R"({"target": "::1"})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": "127.0.0.1"})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": "127.1.1.1"})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": "192.168.1.1"})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        FilterT(R"({"target": "10.0.0.1"})", opfilter::opBuilderHelperPublicIP, "target", {}, FAILURE()),
        // Public IP
        FilterT(R"({"target": "8.8.8.8"})", opfilter::opBuilderHelperPublicIP, "target", {}, SUCCESS()),
        FilterT(R"({"target": "2001:4860:4860::8888"})", opfilter::opBuilderHelperPublicIP, "target", {}, SUCCESS())
        // End of test cases
        ),
    testNameFormatter<FilterOperationTest>("PUBLICIP"));
} // namespace filteroperatestest

// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{
// in_cidr: one or more literal networks, each 'a.b.c.d/nn' (nn in 0..32) or 'a.b.c.d/m.m.m.m'
INSTANTIATE_TEST_SUITE_P(
    BuilderInCidr,
    FilterBuilderTest,
    testing::Values(
        // Wrong number of arguments
        FilterT({}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        // Non-string arguments (an unquoted prefix such as 24 is a JSON number, not a string)
        FilterT({makeValue(R"(1)")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"(24)")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("10.0.0.0/8")"), makeValue(R"(24)")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        // Missing '/': this includes the old two-argument form ('192.168.255.0', '24')
        FilterT({makeValue(R"("192.168.255.255")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.255.0")"), makeValue(R"("24")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.255.0")"), makeValue(R"("255.255.255.0")")},
                opfilter::opBuilderHelperIPCIDR,
                FAILURE()),
        FilterT({makeValue(R"("10.0.0.0/8")"), makeValue(R"("192.168.0.0")")},
                opfilter::opBuilderHelperIPCIDR,
                FAILURE()),
        // Empty side of the '/'
        FilterT({makeValue(R"("/24")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("/")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        // Invalid network
        FilterT({makeValue(R"("192.168.0/24")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("256.0.0.0/8")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("network/24")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("::1/128")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        // Invalid mask
        FilterT({makeValue(R"("192.168.0.0/33")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/-1")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/24x")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/24/8")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/mask")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/255.255.256.0")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/255.255.255")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        // One invalid network among valid ones
        FilterT({makeValue(R"("10.0.0.0/8")"), makeValue(R"("172.16.0.0/33")")},
                opfilter::opBuilderHelperIPCIDR,
                FAILURE()),
        // References are not accepted
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeRef("ref"), makeRef("ref")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeRef("ref"), makeValue(R"("192.168.0.0/24")")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        FilterT({makeValue(R"("192.168.0.0/24")"), makeRef("ref")}, opfilter::opBuilderHelperIPCIDR, FAILURE()),
        // Valid networks
        FilterT({makeValue(R"("192.168.255.0/24")")}, opfilter::opBuilderHelperIPCIDR, SUCCESS()),
        FilterT({makeValue(R"("192.168.255.0/255.255.255.0")")}, opfilter::opBuilderHelperIPCIDR, SUCCESS()),
        FilterT({makeValue(R"("0.0.0.0/0")")}, opfilter::opBuilderHelperIPCIDR, SUCCESS()),
        FilterT({makeValue(R"("192.168.1.1/32")")}, opfilter::opBuilderHelperIPCIDR, SUCCESS()),
        // Host bits set in the network are masked off
        FilterT({makeValue(R"("192.168.255.255/24")")}, opfilter::opBuilderHelperIPCIDR, SUCCESS()),
        // Several networks
        FilterT({makeValue(R"("10.0.0.0/8")"), makeValue(R"("172.16.0.0/12")"), makeValue(R"("192.168.0.0/16")")},
                opfilter::opBuilderHelperIPCIDR,
                SUCCESS()),
        FilterT({makeValue(R"("10.0.0.0/8")"), makeValue(R"("10.0.0.0/255.0.0.0")")},
                opfilter::opBuilderHelperIPCIDR,
                SUCCESS())),
    testNameFormatter<FilterBuilderTest>("InCidr"));

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
INSTANTIATE_TEST_SUITE_P(
    BuilderInCidr,
    FilterOperationTest,
    testing::Values(
        // Prefix mask
        FilterT(R"({"target": "192.168.255.255"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                SUCCESS()),
        FilterT(R"({"target": "192.168.255.0"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                SUCCESS()),
        FilterT(R"({"target": "192.168.254.255"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                FAILURE()),
        FilterT(R"({"target": "192.169.0.0"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                FAILURE()),
        // Dotted mask is equivalent to the prefix
        FilterT(R"({"target": "192.168.255.255"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/255.255.255.0")")},
                SUCCESS()),
        FilterT(R"({"target": "192.168.254.255"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/255.255.255.0")")},
                FAILURE()),
        FilterT(R"({"target": "10.1.2.3"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/8")")},
                SUCCESS()),
        FilterT(R"({"target": "10.1.2.3"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/255.0.0.0")")},
                SUCCESS()),
        FilterT(R"({"target": "11.0.0.1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/8")")},
                FAILURE()),
        FilterT(R"({"target": "11.0.0.1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/255.0.0.0")")},
                FAILURE()),
        // Host bits set in the network are ignored
        FilterT(R"({"target": "192.168.255.1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.255/24")")},
                SUCCESS()),
        // /32 matches one host, /0 matches every IPv4 address
        FilterT(R"({"target": "192.168.1.1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.1.1/32")")},
                SUCCESS()),
        FilterT(R"({"target": "192.168.1.2"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.1.1/32")")},
                FAILURE()),
        FilterT(R"({"target": "8.8.8.8"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("0.0.0.0/0")")},
                SUCCESS()),
        // Several networks: the address must be inside any of them
        FilterT(R"({"target": "10.1.2.3"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/8")"), makeValue(R"("172.16.0.0/12")")},
                SUCCESS()),
        FilterT(R"({"target": "172.16.5.4"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/8")"), makeValue(R"("172.16.0.0/12")")},
                SUCCESS()),
        FilterT(R"({"target": "192.168.1.1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/8")"), makeValue(R"("172.16.0.0/12")")},
                FAILURE()),
        FilterT(R"({"target": "192.168.1.1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("10.0.0.0/8")"), makeValue(R"("172.16.0.0/12")"), makeValue(R"("192.168.0.0/16")")},
                SUCCESS()),
        // Target is not an IPv4 address: IPv6 is never inside an IPv4 network, not even 0.0.0.0/0
        FilterT(R"({"target": "::1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("0.0.0.0/0")")},
                FAILURE()),
        FilterT(R"({"target": "2001:db8::1"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("0.0.0.0/0")")},
                FAILURE()),
        FilterT(R"({"target": "192.168.255.255/24"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                FAILURE()),
        FilterT(R"({"target": "not an ip"})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("0.0.0.0/0")")},
                FAILURE()),
        FilterT(
            R"({"target": ""})", opfilter::opBuilderHelperIPCIDR, "target", {makeValue(R"("0.0.0.0/0")")}, FAILURE()),
        // Target missing or not a string
        FilterT(R"({"target": "192.168.255.255"})",
                opfilter::opBuilderHelperIPCIDR,
                "notTarget",
                {makeValue(R"("192.168.255.0/255.255.255.0")")},
                FAILURE()),
        FilterT(R"({"target": 3232301055})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                FAILURE()),
        FilterT(
            R"({"target": null})", opfilter::opBuilderHelperIPCIDR, "target", {makeValue(R"("0.0.0.0/0")")}, FAILURE()),
        FilterT(R"({"target": ["192.168.255.255"]})",
                opfilter::opBuilderHelperIPCIDR,
                "target",
                {makeValue(R"("192.168.255.0/24")")},
                FAILURE())),
    testNameFormatter<FilterOperationTest>("InCidr"));

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

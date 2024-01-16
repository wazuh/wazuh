#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
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
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
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
} // namespace filteroperatestest

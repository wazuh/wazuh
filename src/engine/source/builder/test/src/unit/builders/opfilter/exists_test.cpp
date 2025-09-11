#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/exists.hpp"

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterBuilderTest,
                         testing::Values(
                             // Wrong arguments number
                             FilterT({makeValue()}, opfilter::existsBuilder, FAILURE()),
                             FilterT({makeValue()}, opfilter::notExistsBuilder, FAILURE()),
                             FilterT({makeRef()}, opfilter::existsBuilder, FAILURE()),
                             FilterT({makeRef()}, opfilter::notExistsBuilder, FAILURE()),
                             // Success case
                             FilterT({}, opfilter::existsBuilder, SUCCESS()),
                             FilterT({}, opfilter::notExistsBuilder, SUCCESS())),
                         testNameFormatter<FilterBuilderTest>("Exists"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(FilterT(R"({"target": 1})", opfilter::existsBuilder, "target", {}, SUCCESS()),
                    FilterT(R"({"target": 1})", opfilter::notExistsBuilder, "target", {}, FAILURE()),
                    FilterT(R"({"target": 1})", opfilter::existsBuilder, "notTarget", {}, FAILURE()),
                    FilterT(R"({"target": 1})", opfilter::notExistsBuilder, "notTarget", {}, SUCCESS())),
    testNameFormatter<FilterOperationTest>("Exists"));

} // namespace filteroperatestest

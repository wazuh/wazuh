#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        /*** RegexMatch ***/
        FilterT({}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"("str")"), makeValue(R"("str")")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"("str")")}, opfilter::opBuilderHelperRegexMatch, SUCCESS()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"("InvalidRegex[")")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"(2)")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"([1,2,3])")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"(3.4)")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperRegexMatch, FAILURE()),
        /*** RegexNotMatch ***/
        FilterT({}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"("str")"), makeValue(R"("str")")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"("str")")}, opfilter::opBuilderHelperRegexNotMatch, SUCCESS()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"("InvalidRegex[")")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"(2)")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"([1,2,3])")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"(3.4)")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperRegexNotMatch, FAILURE())),
    testNameFormatter<FilterBuilderTest>("Regex"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterOperationTest,
                         testing::Values(
                             /*** RegexMatch ***/
                             FilterT(R"({"target": "value"})",
                                     opfilter::opBuilderHelperRegexMatch,
                                     "target",
                                     {makeValue(R"("^value$")")},
                                     SUCCESS()),
                             FilterT(R"({"target": "value"})",
                                     opfilter::opBuilderHelperRegexMatch,
                                     "target",
                                     {makeValue(R"("^value2$")")},
                                     FAILURE()),
                             FilterT(R"({"target": "value"})",
                                     opfilter::opBuilderHelperRegexMatch,
                                     "notTarget",
                                     {makeValue(R"("^value$")")},
                                     FAILURE()),
                             /*** RegexNotMatch ***/
                             FilterT(R"({"target": "value"})",
                                     opfilter::opBuilderHelperRegexNotMatch,
                                     "target",
                                     {makeValue(R"("^value$")")},
                                     FAILURE()),
                             FilterT(R"({"target": "value"})",
                                     opfilter::opBuilderHelperRegexNotMatch,
                                     "target",
                                     {makeValue(R"("^value2$")")},
                                     SUCCESS()),
                             FilterT(R"({"target": "value"})",
                                     opfilter::opBuilderHelperRegexNotMatch,
                                     "notTarget",
                                     {makeValue(R"("^value$")")},
                                     FAILURE())),
                         testNameFormatter<FilterOperationTest>("Regex"));
} // namespace filteroperatestest

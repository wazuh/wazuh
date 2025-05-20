#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/filter.hpp"

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         FilterBuilderTest,
                         testing::Values(
                             // Wrong arguments number
                             FilterT({}, opfilter::filterBuilder, FAILURE()),
                             FilterT({makeValue(), makeValue()}, opfilter::filterBuilder, FAILURE()),
                             // Filter Value
                             FilterT({makeValue()}, opfilter::filterBuilder, SUCCESS()),
                             // Filter Reference
                             FilterT({makeRef()}, opfilter::filterBuilder, SUCCESS())),
                         testNameFormatter<FilterBuilderTest>("DefaultFilter"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        // Value cases
        FilterT(R"({"target": 1})", opfilter::filterBuilder, "target", {makeValue("1")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::filterBuilder, "target", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": 1.2})", opfilter::filterBuilder, "target", {makeValue("1.2")}, SUCCESS()),
        FilterT(R"({"target": 1.2})", opfilter::filterBuilder, "target", {makeValue("1.3")}, FAILURE()),
        FilterT(R"({"target": "hola"})", opfilter::filterBuilder, "target", {makeValue(R"("hola")")}, SUCCESS()),
        FilterT(R"({"target": "hola"})", opfilter::filterBuilder, "target", {makeValue(R"("hola2")")}, FAILURE()),
        FilterT(R"({"target": true})", opfilter::filterBuilder, "target", {makeValue("true")}, SUCCESS()),
        FilterT(R"({"target": true})", opfilter::filterBuilder, "target", {makeValue("false")}, FAILURE()),
        FilterT(R"({"target": [1, 2, 3]})", opfilter::filterBuilder, "target", {makeValue("[1, 2, 3]")}, SUCCESS()),
        FilterT(R"({"target": [1, 2, 3]})", opfilter::filterBuilder, "target", {makeValue("[1, 2, 4]")}, FAILURE()),
        FilterT(R"({"target": {"a": 1, "b": 2}})",
                opfilter::filterBuilder,
                "target",
                {makeValue(R"({"a": 1, "b": 2})")},
                SUCCESS()),
        FilterT(R"({"target": {"a": 1, "b": 2}})",
                opfilter::filterBuilder,
                "target",
                {makeValue(R"({"a": 1, "b": 3})")},
                FAILURE()),
        FilterT(R"({"target": null})", opfilter::filterBuilder, "target", {makeValue("null")}, SUCCESS()),
        FilterT(R"({"target": null})", opfilter::filterBuilder, "target", {makeValue("1")}, FAILURE()),
        // Reference cases
        FilterT(R"({"target": 1, "ref": 1})", opfilter::filterBuilder, "target", {makeRef("ref")}, SUCCESS()),
        FilterT(R"({"target": 1, "ref": 2})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE()),
        FilterT(R"({"target": 1.2, "ref": 1.2})", opfilter::filterBuilder, "target", {makeRef("ref")}, SUCCESS()),
        FilterT(R"({"target": 1.2, "ref": 1.3})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE()),
        FilterT(R"({"target": "hola", "ref": "hola"})", opfilter::filterBuilder, "target", {makeRef("ref")}, SUCCESS()),
        FilterT(
            R"({"target": "hola", "ref": "hola2"})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE()),
        FilterT(R"({"target": true, "ref": true})", opfilter::filterBuilder, "target", {makeRef("ref")}, SUCCESS()),
        FilterT(R"({"target": true, "ref": false})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE()),
        FilterT(R"({"target": [1, 2, 3], "ref": [1, 2, 3]})",
                opfilter::filterBuilder,
                "target",
                {makeRef("ref")},
                SUCCESS()),
        FilterT(R"({"target": [1, 2, 3], "ref": [1, 2, 4]})",
                opfilter::filterBuilder,
                "target",
                {makeRef("ref")},
                FAILURE()),
        FilterT(R"({"target": {"a": 1, "b": 2}, "ref": {"a": 1, "b": 2}})",
                opfilter::filterBuilder,
                "target",
                {makeRef("ref")},
                SUCCESS()),
        FilterT(R"({"target": {"a": 1, "b": 2}, "ref": {"a": 1, "b": 3}})",
                opfilter::filterBuilder,
                "target",
                {makeRef("ref")},
                FAILURE()),
        FilterT(R"({"target": null, "ref": null})", opfilter::filterBuilder, "target", {makeRef("ref")}, SUCCESS()),
        FilterT(R"({"target": null, "ref": 1})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE()),
        // Missing target field
        FilterT(R"({"other": 1})", opfilter::filterBuilder, "target", {makeValue("1")}, FAILURE()),
        FilterT(R"({"ref": 1})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE()),
        // Missing reference field
        FilterT(R"({"target": 1})", opfilter::filterBuilder, "target", {makeRef("ref")}, FAILURE())),
    testNameFormatter<FilterOperationTest>("DefaultFilter"));

} // namespace filteroperatestest

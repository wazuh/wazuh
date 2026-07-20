#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/map.hpp"

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapBuilderTest,
                         testing::Values(
                             // Wrong arguments number
                             MapT({}, opmap::mapBuilder, FAILURE()),
                             MapT({makeValue(), makeValue()}, opmap::mapBuilder, FAILURE()),
                             // Map Value
                             MapT({makeValue()}, opmap::mapBuilder, SUCCESS()),
                             // Map Reference
                             MapT({makeRef()}, opmap::mapBuilder, SUCCESS())),
                         testNameFormatter<MapBuilderTest>("DefaultMap"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        // Value cases
        MapT("{}", opmap::mapBuilder, {makeValue("1")}, SUCCESS(json::Json("1"))),
        MapT("{}", opmap::mapBuilder, {makeValue("1.2")}, SUCCESS(json::Json("1.2"))),
        MapT("{}", opmap::mapBuilder, {makeValue(R"("hola")")}, SUCCESS(json::Json(R"("hola")"))),
        MapT("{}", opmap::mapBuilder, {makeValue("true")}, SUCCESS(json::Json("true"))),
        MapT("{}", opmap::mapBuilder, {makeValue("[1, 2, 3]")}, SUCCESS(json::Json("[1, 2, 3]"))),
        MapT("{}", opmap::mapBuilder, {makeValue(R"({"a": 1, "b": 2})")}, SUCCESS(json::Json(R"({"a": 1, "b": 2})"))),
        MapT("{}", opmap::mapBuilder, {makeValue("null")}, SUCCESS(json::Json("null"))),
        // Reference cases
        MapT(R"({"ref": 1})", opmap::mapBuilder, {makeRef("ref")}, SUCCESS(json::Json("1"))),
        MapT(R"({"ref": 1.2})", opmap::mapBuilder, {makeRef("ref")}, SUCCESS(json::Json("1.2"))),
        MapT(R"({"ref": "hola"})", opmap::mapBuilder, {makeRef("ref")}, SUCCESS(json::Json(R"("hola")"))),
        MapT(R"({"ref": true})", opmap::mapBuilder, {makeRef("ref")}, SUCCESS(json::Json("true"))),
        MapT(R"({"ref": [1, 2, 3]})", opmap::mapBuilder, {makeRef("ref")}, SUCCESS(json::Json("[1, 2, 3]"))),
        MapT(R"({"ref": {"a": 1, "b": 2}})",
             opmap::mapBuilder,
             {makeRef("ref")},
             SUCCESS(json::Json(R"({"a": 1, "b": 2})"))),
        MapT(R"({"ref": null})", opmap::mapBuilder, {makeRef("ref")}, SUCCESS(json::Json("null"))),
        // Reference not found
        MapT("{}", opmap::mapBuilder, {makeRef("ref")}, FAILURE())),
    testNameFormatter<MapOperationTest>("DefaultMap"));
} // namespace mapoperatestest

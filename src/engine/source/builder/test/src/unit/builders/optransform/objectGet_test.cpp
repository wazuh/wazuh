#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
template<typename... Refs>
auto customRefExpected(base::Event value, Refs... refs)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        for (auto ref : {refs...})
        {
            EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        }

        return value;
    };
}

template<typename... Refs>
auto customRefExpected(Refs... refs)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        for (auto ref : {refs...})
        {
            EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        }

        return None {};
    };
}

} // namespace

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderTest,
    testing::Values(
        /*** Get Value ***/
        TransformT({}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeValue(R"({})")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"({})")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key")}, opBuilderHelperGetValue, SUCCESS(customRefExpected("obj", "key"))),
        TransformT({makeValue(R"({"key": "value"})"), makeRef("ref")},
                   opBuilderHelperGetValue,
                   SUCCESS(customRefExpected("ref"))),
        /*** Merge Value ***/
        TransformT({}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeValue(R"({})")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"({})")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key")},
                   opBuilderHelperMergeValue,
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customRefExpected("obj", "key")(mocks);
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeValue(R"({"key": "value"})"), makeRef("ref")},
                   opBuilderHelperMergeValue,
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customRefExpected("ref")(mocks);
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       }))),
    testNameFormatter<TransformBuilderTest>("ObjectGet"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(
        /*** Get Value ***/
        TransformT(R"({"ref": "key"})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"key": "value"})"), makeRef("ref")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "key", "target": "value"})"), "ref"))),
        TransformT(R"({"ref1": "key", "ref2": {"key": "value"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   SUCCESS(customRefExpected(
                       makeEvent(R"({"ref1": "key", "ref2": {"key": "value"}, "target": "value"})"), "ref1", "ref2"))),
        TransformT(R"({"ref": "key"})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"key1": "value"})"), makeRef("ref")},
                   FAILURE(customRefExpected("ref"))),
        TransformT(R"({"ref1": "key", "ref2": {"key1": "value"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2"))),
        TransformT(R"({"notRef": "key"})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"key": "value"})"), makeRef("ref")},
                   FAILURE(customRefExpected("ref"))),
        TransformT(R"({"notRef1": "key", "ref2": {"key": "value"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2"))),
        TransformT(R"({"ref1": "key", "notRef2": {"key": "value"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2"))),
        /*** Merge Value ***/
        TransformT(R"({"ref": "key", "target": {"k0": "v0"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"k1": "v1"}})"), makeRef("ref")},
                   SUCCESS(customRefExpected(
                       makeEvent(R"({"ref": "key", "target": {"k0": "v0", "k1": "v1"}})"), "ref", "target"))),
        TransformT(
            R"({"ref1": "key", "ref2": {"key": {"k0": "v0"}}, "target": {"k1": "v1"}})",
            opBuilderHelperMergeValue,
            "target",
            {makeRef("ref2"), makeRef("ref1")},
            SUCCESS(customRefExpected(
                makeEvent(R"({"ref1": "key", "ref2": {"key": {"k0": "v0"}}, "target": {"k1": "v1", "k0": "v0"}})"),
                "ref1",
                "ref2",
                "target"))),
        TransformT(R"({"ref": "key", "target": ["v0"]})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": ["v1"]})"), makeRef("ref")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "key", "target": ["v0", "v1"]})"), "ref", "target"))),
        TransformT(
            R"({"ref1": "key", "ref2": {"key": ["v0"]}, "target": ["v1"]})",
            opBuilderHelperMergeValue,
            "target",
            {makeRef("ref2"), makeRef("ref1")},
            SUCCESS(customRefExpected(makeEvent(R"({"ref1": "key", "ref2": {"key": ["v0"]}, "target": ["v1", "v0"]})"),
                                      "ref1",
                                      "ref2",
                                      "target"))),
        TransformT(R"({"ref": "key", "target": {"k0": "v0"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": ["v1"]})"), makeRef("ref")},
                   FAILURE(customRefExpected("ref", "target"))),
        TransformT(R"({"ref": "key", "target": ["v0"]})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"k0": "v0"}})"), makeRef("ref")},
                   FAILURE(customRefExpected("ref", "target"))),
        TransformT(R"({"ref1": "key", "ref2": {"key": ["v1"]}, "target": {"k0": "v0"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2", "target"))),
        TransformT(R"({"ref1": "key", "ref2": {"key": {"k0": "v0"}}, "target": ["v1"]})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2", "target"))),
        TransformT(R"({"notRef": "key", "target": {"k0": "v0"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"k1": "v1"}})"), makeRef("ref")},
                   FAILURE(customRefExpected("ref", "target"))),
        TransformT(R"({"notRef": "key", "ref2": {"key": {"k0": "v0"}}, "target": {"k1": "v1"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2", "target"))),
        TransformT(R"({"ref1": "key", "notRef2": {"key": {"k0": "v0"}}, "target": {"k1": "v1"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2", "target"))),
        TransformT(R"({"ref": "key"})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"k1": "v1"}})"), makeRef("ref")},
                   FAILURE(customRefExpected("ref", "target"))),
        TransformT(R"({"ref1": "key", "ref2": {"key": {"k0": "v0"}}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(customRefExpected("ref1", "ref2", "target")))),
    testNameFormatter<TransformOperationTest>("ObjectGet"));
} // namespace transformoperatestest

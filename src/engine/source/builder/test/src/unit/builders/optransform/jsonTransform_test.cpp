#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
auto customRefExpected()
{
    return [](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

} // namespace

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         TransformBuilderTest,
                         testing::Values(
                             /*** Delete Field ***/
                             TransformT({}, opBuilderHelperDeleteField, SUCCESS()),
                             TransformT({makeValue(R"("value")")}, opBuilderHelperDeleteField, FAILURE()),
                             TransformT({makeRef("ref")}, opBuilderHelperDeleteField, FAILURE()),
                             /*** Rename Field ***/
                             TransformT({}, opBuilderHelperRenameField, FAILURE()),
                             TransformT({makeValue(R"("value")")}, opBuilderHelperRenameField, FAILURE()),
                             TransformT({makeRef("ref")}, opBuilderHelperRenameField, SUCCESS()),
                             TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperRenameField, FAILURE()),
                             /*** Merge ***/
                             TransformT({}, opBuilderHelperMerge, FAILURE()),
                             TransformT({makeValue(R"("value")")}, opBuilderHelperMerge, FAILURE()),
                             TransformT({makeRef("ref")}, opBuilderHelperMerge, SUCCESS()),
                             TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperMerge, FAILURE()),
                             /*** Merge Recursive ***/
                             TransformT({}, opBuilderHelperMergeRecursively, FAILURE()),
                             TransformT({makeValue(R"("value")")}, opBuilderHelperMergeRecursively, FAILURE()),
                             TransformT({makeRef("ref")}, opBuilderHelperMergeRecursively, SUCCESS()),
                             TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperMergeRecursively, FAILURE()),
                             /*** Erase Custom Fields ***/
                             TransformT({},
                                        opBuilderHelperEraseCustomFields,
                                        SUCCESS(
                                            [](const Mocks& mocks)
                                            {
                                                EXPECT_CALL(*mocks.ctx, schemaPtr()).WillOnce(testing::Return(nullptr));
                                                return None {};
                                            })),
                             TransformT({makeValue(R"("value")")}, opBuilderHelperEraseCustomFields, FAILURE()),
                             TransformT({makeRef("ref")}, opBuilderHelperEraseCustomFields, FAILURE())),
                         testNameFormatter<TransformBuilderTest>("JsonTransform"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(
        /*** Delete Field ***/
        TransformT(R"({"target": "value"})", opBuilderHelperDeleteField, "target", {}, SUCCESS(makeEvent(R"({})"))),
        TransformT(R"({"target": 1})", opBuilderHelperDeleteField, "target", {}, SUCCESS(makeEvent(R"({})"))),
        TransformT(R"({"target": {"a": "b"}})", opBuilderHelperDeleteField, "target", {}, SUCCESS(makeEvent(R"({})"))),
        TransformT(R"({"target": {"a": "b"}})",
                   opBuilderHelperDeleteField,
                   "target.a",
                   {},
                   SUCCESS(makeEvent(R"({"target":{}})"))),
        TransformT(R"({"target": []})", opBuilderHelperDeleteField, "target", {}, SUCCESS(makeEvent(R"({})"))),
        TransformT(R"({"target": true})", opBuilderHelperDeleteField, "target", {}, SUCCESS(makeEvent(R"({})"))),
        TransformT(R"({"target": null})", opBuilderHelperDeleteField, "target", {}, SUCCESS(makeEvent(R"({})"))),
        TransformT(R"({"target": "value", "other": "value"})",
                   opBuilderHelperDeleteField,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"other":"value"})"))),
        TransformT(R"({"notTarget": "value"})", opBuilderHelperDeleteField, "target", {}, FAILURE()),
        /*** Rename Field ***/
        TransformT(R"({"target": "value"})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"ref":"value"})"))),
        TransformT(R"({"target": 1})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"ref":1})"))),
        TransformT(R"({"target": {"a": "b"}})",
                   opBuilderHelperRenameField,
                   "target.a",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{},"ref":"b"})"))),
        TransformT(R"({"target": {"a": "b"}})",
                   opBuilderHelperRenameField,
                   "target.a",
                   {makeRef("target.c")},
                   SUCCESS(makeEvent(R"({"target":{"c": "b"}})"))),
        TransformT(R"({"target": []})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"ref":[]})"))),
        TransformT(R"({"target": true})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"ref":true})"))),
        TransformT(R"({"target": null})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"ref":null})"))),
        TransformT(R"({"target": "value"})", opBuilderHelperRenameField, "notTarget", {makeRef("ref")}, FAILURE()),
        TransformT(R"({"target": "value", "ref": "value"})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   FAILURE()),
        /*** Merge ***/
        TransformT(R"({"target": [1, 3], "ref": [2, 4]})",
                   opBuilderHelperMerge,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":[1,3,2,4]})"))),
        TransformT(R"({"target": [[1], [3]], "ref": [[2], [4]]})",
                   opBuilderHelperMerge,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":[[1],[3],[2],[4]]})"))),
        TransformT(R"({"target": {"a": "b"}, "ref": {"c": "d"}})",
                   opBuilderHelperMerge,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":"b","c":"d"}})"))),
        TransformT(R"({"target": {"a": {"b": "c"}}, "ref": {"a": "d"}})",
                   opBuilderHelperMerge,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":"d"}})"))),
        TransformT(R"({"target": {"a": {"b": "c"}}, "ref": {"a": {"d": "e"}}})",
                   opBuilderHelperMerge,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":{"d":"e"}}})"))),
        TransformT(
            R"({"target": {}, "ref": {"a": "d"}})", opBuilderHelperMerge, "notTarget", {makeRef("ref")}, FAILURE()),
        TransformT(
            R"({"target": {}, "ref": {"a": "d"}})", opBuilderHelperMerge, "target", {makeRef("notRef")}, FAILURE()),
        TransformT(R"({"target": {}, "ref": []})", opBuilderHelperMerge, "target", {makeRef("ref")}, FAILURE()),
        TransformT(R"({"target": 1, "ref": {}})", opBuilderHelperMerge, "target", {makeRef("ref")}, FAILURE()),
        TransformT(R"({"target": 1.1, "ref": {}})", opBuilderHelperMerge, "target", {makeRef("ref")}, FAILURE()),
        TransformT(R"({"target": true, "ref": {}})", opBuilderHelperMerge, "target", {makeRef("ref")}, FAILURE()),
        TransformT(R"({"target": null, "ref": {}})", opBuilderHelperMerge, "target", {makeRef("ref")}, FAILURE()),
        /*** Merge Recursive ***/
        TransformT(R"({"target": [1, 3], "ref": [2, 4]})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":[1,3,2,4]})"))),
        TransformT(R"({"target": [[1], [3]], "ref": [[2], [4]]})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":[[1],[3],[2],[4]]})"))),
        TransformT(R"({"target": {"a": "b"}, "ref": {"c": "d"}})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":"b","c":"d"}})"))),
        TransformT(R"({"target": {"a": {"b": "c"}}, "ref": {"a": "d"}})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":"d"}})"))),
        TransformT(R"({"target": {"a": {"b": "c"}}, "ref": {"a": {"d": "e"}}})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":{"b":"c","d":"e"}}})"))),
        TransformT(R"({"target": {}, "ref": {"a": "d"}})",
                   opBuilderHelperMergeRecursively,
                   "notTarget",
                   {makeRef("ref")},
                   FAILURE()),
        TransformT(R"({"target": {}, "ref": {"a": "d"}})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("notRef")},
                   FAILURE()),
        TransformT(
            R"({"target": {}, "ref": []})", opBuilderHelperMergeRecursively, "target", {makeRef("ref")}, FAILURE()),
        TransformT(
            R"({"target": 1, "ref": {}})", opBuilderHelperMergeRecursively, "target", {makeRef("ref")}, FAILURE()),
        TransformT(
            R"({"target": 1.1, "ref": {}})", opBuilderHelperMergeRecursively, "target", {makeRef("ref")}, FAILURE()),
        TransformT(
            R"({"target": true, "ref": {}})", opBuilderHelperMergeRecursively, "target", {makeRef("ref")}, FAILURE()),
        TransformT(
            R"({"target": null, "ref": {}})", opBuilderHelperMergeRecursively, "target", {makeRef("ref")}, FAILURE()),
        /*** Erase Custom Fields ***/
        TransformT(R"({"target": "value"})",
                   opBuilderHelperEraseCustomFields,
                   ".",
                   {},
                   SUCCESS(
                       [](const Mocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, schemaPtr()).WillOnce(testing::Return(mocks.schema));
                           EXPECT_CALL(*mocks.schema, hasField(DotPath("target"))).WillOnce(testing::Return(false));
                           return makeEvent(R"({})");
                       })),
        TransformT(R"({"target": "value"})",
                   opBuilderHelperEraseCustomFields,
                   ".",
                   {},
                   SUCCESS(
                       [](const Mocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, schemaPtr()).WillOnce(testing::Return(mocks.schema));
                           EXPECT_CALL(*mocks.schema, hasField(DotPath("target"))).WillOnce(testing::Return(true));
                           return makeEvent(R"({"target": "value"})");
                       })),
        TransformT(R"({"t1": "value", "t2": "value"})",
                   opBuilderHelperEraseCustomFields,
                   ".",
                   {},
                   SUCCESS(
                       [](const Mocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, schemaPtr()).WillOnce(testing::Return(mocks.schema));
                           EXPECT_CALL(*mocks.schema, hasField(DotPath("t1"))).WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.schema, hasField(DotPath("t2"))).WillOnce(testing::Return(false));
                           return makeEvent(R"({"t1": "value"})");
                       })),
        TransformT(R"({"target": "value"})",
                   opBuilderHelperEraseCustomFields,
                   "notTarget",
                   {},
                   SUCCESS(
                       [](const Mocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, schemaPtr()).WillOnce(testing::Return(mocks.schema));
                           return makeEvent(R"({"target": "value"})");
                       }))),
    testNameFormatter<TransformOperationTest>("JsonTransform"));
} // namespace transformoperatestest

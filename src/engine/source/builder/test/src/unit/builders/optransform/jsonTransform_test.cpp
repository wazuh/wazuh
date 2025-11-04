#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
auto customRefExpected()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
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
        /*** Delete Field ***/
        TransformT({}, opBuilderHelperDeleteField, SUCCESS()),
        TransformT({makeValue(R"("value")")}, opBuilderHelperDeleteField, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperDeleteField, FAILURE()),
        TransformT({},
                   opBuilderHelperDeleteField,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),

        /*** Delete Fields With Value***/
        TransformT({}, opBuilderHelperDeleteFieldsWithValue, FAILURE()),
        TransformT({makeValue(R"("x")"), makeRef("ref")}, opBuilderHelperDeleteFieldsWithValue, FAILURE()),
        TransformT({makeValue(R"("x")")}, opBuilderHelperDeleteFieldsWithValue, SUCCESS()),
        TransformT({makeRef("ref")}, opBuilderHelperDeleteFieldsWithValue, SUCCESS()),
        TransformT({makeRef("ref")},
                   opBuilderHelperDeleteFieldsWithValue,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),

        /*** Rename Field ***/
        TransformT({}, opBuilderHelperRenameField, FAILURE()),
        TransformT({makeValue(R"("value")")}, opBuilderHelperRenameField, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperRenameField, SUCCESS()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperRenameField, FAILURE()),
        TransformT({makeRef("ref")},
                   opBuilderHelperRenameField,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("ref")))
                               .WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeRef("ref")},
                   opBuilderHelperRenameField,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("ref")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Merge ***/
        TransformT({}, opBuilderHelperMerge, FAILURE()),
        TransformT({makeValue(R"("value")")}, opBuilderHelperMerge, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperMerge, SUCCESS()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperMerge, FAILURE()),
        TransformT({makeRef("ref")},
                   opBuilderHelperMerge,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Merge Recursive ***/
        TransformT({}, opBuilderHelperMergeRecursively, FAILURE()),
        TransformT({makeValue(R"("value")")}, opBuilderHelperMergeRecursively, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperMergeRecursively, SUCCESS()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperMergeRecursively, FAILURE()),
        TransformT({makeRef("ref")},
                   opBuilderHelperMergeRecursively,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Erase Custom Fields ***/
        TransformT({},
                   opBuilderHelperEraseCustomFields,
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, validatorPtr()).WillOnce(testing::Return(nullptr));
                           return None {};
                       })),
        TransformT({makeValue(R"("value")")}, opBuilderHelperEraseCustomFields, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperEraseCustomFields, FAILURE()),
        /*** Sanitize Fields ***/
        TransformT({}, opBuilderHelperSanitizeFields, SUCCESS()),
        TransformT({makeValue(R"("value")")}, opBuilderHelperSanitizeFields, FAILURE()),
        TransformT({makeValue("true")}, opBuilderHelperSanitizeFields, SUCCESS()),
        TransformT({makeRef("ref")}, opBuilderHelperSanitizeFields, FAILURE())),
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

        /*** Delete Fields With Value ***/
        // string by value
        TransformT(R"({"target":{"a":"N/A","b":"ok","c":"N/A"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   SUCCESS(makeEvent(R"({"target":{"b":"ok"}})"))),

        // string by reference (external field)
        TransformT(R"({"target":{"a":"X","b":"ok","c":"X"},"ref":"X"})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"b":"ok"},"ref":"X"})"))),

        // string no-op (no matches)
        TransformT(R"({"target":{"a":"foo","b":"ok"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   SUCCESS(makeEvent(R"({"target":{"a":"foo","b":"ok"}})"))),

        // snapshot ref inside same object (reference is one of the children)
        TransformT(R"({"target":{"user":"N/A","group":"N/A","other":"x"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("target.user")},
                   SUCCESS(makeEvent(R"({"target":{"other":"x"}})"))),

        // int by value
        TransformT(R"({"target":{"a":1,"b":2,"c":1}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("1")},
                   SUCCESS(makeEvent(R"({"target":{"b":2}})"))),

        // int by reference (external field)
        TransformT(R"({"target":{"a":1,"b":2,"c":1},"ref":1})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"b":2},"ref":1})"))),

        // int no-op
        TransformT(R"({"target":{"a":1,"b":2}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("3")},
                   SUCCESS(makeEvent(R"({"target":{"a":1,"b":2}})"))),

        // double by value
        TransformT(R"({"target":{"a":1.0,"b":2.0,"c":1.0}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("1.0")},
                   SUCCESS(makeEvent(R"({"target":{"b":2.0}})"))),

        // double by reference (external field)
        TransformT(R"({"target":{"a":1.5,"b":2.0,"c":1.5},"ref":1.5})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"b":2.0},"ref":1.5})"))),

        // bool by value (true)
        TransformT(R"({"target":{"a":true,"b":false,"c":true}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("true")},
                   SUCCESS(makeEvent(R"({"target":{"b":false}})"))),

        // bool by reference (false)
        TransformT(R"({"target":{"a":false,"b":true,"c":false},"ref":false})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"b":true},"ref":false})"))),

        // null by value
        TransformT(R"({"target":{"a":null,"b":"x","c":1}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("null")},
                   SUCCESS(makeEvent(R"({"target":{"b":"x","c":1}})"))),

        // null by reference (external field)
        TransformT(R"({"target":{"a":1,"b":null,"c":"x"},"ref":null})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"a":1,"c":"x"},"ref":null})"))),

        // object equality by reference
        TransformT(R"({"target":{"a":{"k":1},"b":{"k":2},"c":{"k":1}},"ref":{"k":1}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"b":{"k":2}},"ref":{"k":1}})"))),

        // array equality by reference
        TransformT(R"({"target":{"a":[1,2],"b":[3],"c":[1,2]},"ref":[1,2]})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"b":[3]},"ref":[1,2]})"))),

        // target missing -> failure
        TransformT(R"({"notTarget":{"a":"N/A"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   FAILURE()),

        // target is not an object (string) -> failure
        TransformT(
            R"({"target":"N/A"})", opBuilderHelperDeleteFieldsWithValue, "target", {makeValue(R"("N/A")")}, FAILURE()),

        // target is not an object (number) -> failure
        TransformT(R"({"target":1})", opBuilderHelperDeleteFieldsWithValue, "target", {makeValue("1")}, FAILURE()),

        // target is not an object (double) -> failure
        TransformT(R"({"target":1.0})", opBuilderHelperDeleteFieldsWithValue, "target", {makeValue("1.0")}, FAILURE()),

        // target is not an object (bool) -> failure
        TransformT(
            R"({"target":true})", opBuilderHelperDeleteFieldsWithValue, "target", {makeValue("true")}, FAILURE()),

        // target is not an object (array) -> failure
        TransformT(
            R"({"target":[1,2,3]})", opBuilderHelperDeleteFieldsWithValue, "target", {makeValue("1")}, FAILURE()),

        // target is not an object (null) -> failure
        TransformT(
            R"({"target":null})", opBuilderHelperDeleteFieldsWithValue, "target", {makeValue("null")}, FAILURE()),

        // key with '/' — by value
        TransformT(R"({"target":{"a/b":"N/A","x":1}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   SUCCESS(makeEvent(R"({"target":{"x":1}})"))),

        // key with '~' — by value
        TransformT(R"({"target":{"a~b":"N/A","x":"ok"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   SUCCESS(makeEvent(R"({"target":{"x":"ok"}})"))),

        // both keys ('/' and '~') — by value
        TransformT(R"({"target":{"a/b":"N/A","a~b":"N/A","z":"keep"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   SUCCESS(makeEvent(R"({"target":{"z":"keep"}})"))),

        // key with '/' — by external reference
        TransformT(R"({"target":{"a/b":"X","z":"ok"},"ref":"X"})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"z":"ok"},"ref":"X"})"))),

        // key with '~' — by external reference
        TransformT(R"({"target":{"a~b":"X","z":0},"ref":"X"})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":{"z":0},"ref":"X"})"))),

        // snapshot ref inside same object — removes child with '/'
        TransformT(R"({"target":{"user":"N/A","a/b":"N/A","other":123}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("target.user")},
                   SUCCESS(makeEvent(R"({"target":{"other":123}})"))),

        // snapshot ref inside same object — removes child with '~'
        TransformT(R"({"target":{"user":false,"a~b":false,"keep":true}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeRef("target.user")},
                   SUCCESS(makeEvent(R"({"target":{"keep":true}})"))),

        // no-op with special keys (no matches)
        TransformT(R"({"target":{"a/b":"keep","a~b":"also-keep"}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue(R"("N/A")")},
                   SUCCESS(makeEvent(R"({"target":{"a/b":"keep","a~b":"also-keep"}})"))),

        // number match with '/' key — by value
        TransformT(R"({"target":{"a/b":10,"x":11}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("10")},
                   SUCCESS(makeEvent(R"({"target":{"x":11}})"))),

        // boolean match with '~' key — by value
        TransformT(R"({"target":{"a~b":true,"x":false}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("true")},
                   SUCCESS(makeEvent(R"({"target":{"x":false}})"))),

        // Deletes only the dotted key "a.b"
        TransformT(R"({"target":{"a.b":10,"x":11}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("10")},
                   SUCCESS(makeEvent(R"({"target":{"x":11}})"))),

        // Deletes "a.b" but keeps nested a/b
        TransformT(R"({"target":{"a":{"b":999},"a.b":10,"x":0}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("10")},
                   SUCCESS(makeEvent(R"({"target":{"a":{"b":999},"x":0}})"))),

        // Deletes the literal key "."
        TransformT(R"({"target":{".":10,"x":11}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("10")},
                   SUCCESS(makeEvent(R"({"target":{"x":11}})"))),

        // Deletes the empty-string key ""
        TransformT(R"({"target":{"":10,"x":11}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("10")},
                   SUCCESS(makeEvent(R"({"target":{"x":11}})"))),

        // Deletes dotted ".", and "" keys; keeps escaped names and others
        TransformT(R"({"target":{"a.b":10,".":10,"":10,"a/b":10,"a~b":10,"keep":1}})",
                   opBuilderHelperDeleteFieldsWithValue,
                   "target",
                   {makeValue("10")},
                   SUCCESS(makeEvent(R"({"target":{"keep":1}})"))),

        /*** Rename Field ***/
        TransformT(R"({"ref": "value"})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":"value"})"))),
        TransformT(R"({"ref": 1})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":1})"))),
        TransformT(R"({"target": {"c": "d"}, "ref": "b"})",
                   opBuilderHelperRenameField,
                   "target.a",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target": {"c": "d", "a": "b"}})"))),
        TransformT(R"({"target": {"c": "d"}, "ref": {"a": "b"}})",
                   opBuilderHelperRenameField,
                   "target.a",
                   {makeRef("ref.a")},
                   SUCCESS(makeEvent(R"({"target": {"c": "d", "a": "b"}, "ref": {}})"))),
        TransformT(R"({"target": {"a": "b"}})",
                   opBuilderHelperRenameField,
                   "target.c",
                   {makeRef("target.a")},
                   SUCCESS(makeEvent(R"({"target":{"c": "b"}})"))),
        TransformT(R"({"ref": []})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":[]})"))),
        TransformT(R"({"ref": true})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":true})"))),
        TransformT(R"({"ref": null})",
                   opBuilderHelperRenameField,
                   "target",
                   {makeRef("ref")},
                   SUCCESS(makeEvent(R"({"target":null})"))),
        TransformT(R"({"ref": "value"})", opBuilderHelperRenameField, "target", {makeRef("notRef")}, FAILURE()),
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
        TransformT(R"({"target": {"a": {"b": "c"}}, "ref": {"a": {"d": "e"}}})",
                   opBuilderHelperMerge,
                   "target",
                   {makeRef("ref")},
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                               .WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.a.d")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
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
        TransformT(R"({"target": {"a": {"b": "c"}}, "ref": {"a": {"d": "e"}}})",
                   opBuilderHelperMergeRecursively,
                   "target",
                   {makeRef("ref")},
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                               .WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.a.d")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Erase Custom Fields ***/
        TransformT(R"({"target": "value"})",
                   opBuilderHelperEraseCustomFields,
                   ".",
                   {},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, validatorPtr()).WillOnce(testing::Return(mocks.validator));
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("target"))).WillOnce(testing::Return(false));
                           return makeEvent(R"({})");
                       })),
        TransformT(R"({"target": "value"})",
                   opBuilderHelperEraseCustomFields,
                   ".",
                   {},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, validatorPtr()).WillOnce(testing::Return(mocks.validator));
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("target"))).WillOnce(testing::Return(true));
                           return makeEvent(R"({"target": "value"})");
                       })),
        TransformT(R"({"t1": "value", "t2": "value"})",
                   opBuilderHelperEraseCustomFields,
                   ".",
                   {},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, validatorPtr()).WillOnce(testing::Return(mocks.validator));
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("t1"))).WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("t2"))).WillOnce(testing::Return(false));
                           return makeEvent(R"({"t1": "value"})");
                       })),
        TransformT(R"({"target": "value"})",
                   opBuilderHelperEraseCustomFields,
                   "notTarget",
                   {},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           EXPECT_CALL(*mocks.ctx, validatorPtr()).WillOnce(testing::Return(mocks.validator));
                           return makeEvent(R"({"target": "value"})");
                       })),
        /*** Sanitize Fields ***/
        TransformT(R"({"target":{"Full Name":"Ana","e-mail":"x","Pais":"AR"}})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":{"full_name":"Ana","e_mail":"x","pais":"AR"}})"))),
        TransformT(R"({"target":{"A\\B:C D":1}})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":{"a_b_c_d":1}})"))),
        TransformT(R"({"target":{"a\\\\b///c::d  e":1}})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":{"a_b_c_d_e":1}})"))),
        TransformT(R"({"target":{"hello what if":1,"hello-what-if":2}})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   FAILURE()),
        TransformT(R"({"target":{"123abc":1,"x":2}})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":{"123abc":1,"x":2}})"))),
        TransformT(R"({"target":["Hello world","hello-world","HELLO  world"]})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":["hello_world","hello_world","hello_world"]})"))),
        TransformT(R"({"target":[{"Full Name":"Ana"},{"e-mail":"x"}]})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":[{"full_name":"Ana"},{"e_mail":"x"}]})"))),
        TransformT(R"({"target":["Hello world", {"Full Name":"Ana"}]})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target":["hello_world",{"full_name":"Ana"}]})"))),
        TransformT(R"({"target":[1, {"a":1}]})", opBuilderHelperSanitizeFields, "target", {}, FAILURE()),
        TransformT(R"({"target":{"a":{"B-C":{"D E":1}}}})",
                   opBuilderHelperSanitizeFields,
                   "target",
                   {makeValue("true")},
                   SUCCESS(makeEvent(R"({"target":{"a":{"b_c":{"d_e":1}}}})"))),
        TransformT(R"({"target":{"a":{"X Y":1},"b":{"Z W":2}}})",
                   opBuilderHelperSanitizeFields,
                   "target.a",
                   {},
                   SUCCESS(makeEvent(R"({"target":{"a":{"x_y":1},"b":{"Z W":2}}})")))),
    testNameFormatter<TransformOperationTest>("JsonTransform"));
} // namespace transformoperatestest

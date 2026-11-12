// SPDX-License-Identifier: AGPL-3.0-or-later
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

// Mocks of a lookup whose object and key are both literals: only the target validation touches the schema
auto literalArgsExpected()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        return None {};
    };
}

auto literalArgsExpected(base::Event value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        return value;
    };
}

} // namespace

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderTest,
    testing::Values(
        /*** lookup(object, key) ***/
        TransformT({}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeValue(R"({})")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"({})")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key")}, opBuilderHelperGetValue, SUCCESS(customRefExpected("obj", "key"))),
        TransformT({makeValue(R"({"key": "value"})"), makeRef("ref")},
                   opBuilderHelperGetValue,
                   SUCCESS(customRefExpected("ref"))),
        /*** The key may be a literal string ***/
        TransformT({makeRef("obj"), makeValue(R"("key")")}, opBuilderHelperGetValue, SUCCESS(customRefExpected("obj"))),
        TransformT({makeValue(R"({"key": "value"})"), makeValue(R"("key")")},
                   opBuilderHelperGetValue,
                   SUCCESS(literalArgsExpected())),
        TransformT({makeRef("obj"), makeValue("1")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeValue(R"("")")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeValue("true")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeValue("null")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeValue(R"(["key"])")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeValue(R"("object")"), makeValue(R"("key")")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeValue(R"(["object"])"), makeRef("key")}, opBuilderHelperGetValue, FAILURE()),
        /*** lookup takes exactly two arguments: there is no 'deep' mode ***/
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("deep")")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeValue(R"("key")"), makeValue(R"("deep")")}, opBuilderHelperGetValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key")},
                   opBuilderHelperGetValue,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** lookup_merge(object, key[, 'deep']) ***/
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
                       })),
        /*** The key may be a literal string ***/
        TransformT({makeRef("obj"), makeValue(R"("key")")},
                   opBuilderHelperMergeValue,
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customRefExpected("obj")(mocks);
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeValue(R"({"key": {}})"), makeValue(R"("key")")},
                   opBuilderHelperMergeValue,
                   SUCCESS(customRefExpected("targetField"))),
        TransformT({makeRef("obj"), makeValue("1")}, opBuilderHelperMergeValue, FAILURE()),
        /*** The optional third argument must be the literal 'deep' ***/
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("deep")")},
                   opBuilderHelperMergeValue,
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customRefExpected("obj", "key")(mocks);
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeRef("obj"), makeValue(R"("key")"), makeValue(R"("deep")")},
                   opBuilderHelperMergeValue,
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customRefExpected("obj")(mocks);
                           EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeValue(R"({"key": {}})"), makeValue(R"("key")"), makeValue(R"("deep")")},
                   opBuilderHelperMergeValue,
                   SUCCESS(customRefExpected("targetField"))),
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("shallow")")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("DEEP")")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("")")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key"), makeValue("true")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key"), makeValue("null")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key"), makeRef("deep")}, opBuilderHelperMergeValue, FAILURE()),
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("deep")"), makeValue(R"("deep")")},
                   opBuilderHelperMergeValue,
                   FAILURE()),
        TransformT({makeRef("obj"), makeRef("key")},
                   opBuilderHelperMergeValue,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT({makeRef("obj"), makeRef("key"), makeValue(R"("deep")")},
                   opBuilderHelperMergeValue,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
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
        /*** lookup(object, key) ***/
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
        TransformT(R"({"ref1": "key", "ref2": {"key": {"a": "value"}}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                               .WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.a")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** A literal key ***/
        TransformT(R"({"ref": {"key": "value"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref"), makeValue(R"("key")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": {"key": "value"}, "target": "value"})"), "ref"))),
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"key": "value"})"), makeValue(R"("key")")},
                   SUCCESS(literalArgsExpected(makeEvent(R"({"target": "value"})")))),
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"key": "value"})"), makeValue(R"("other")")},
                   FAILURE(literalArgsExpected())),
        TransformT(R"({"notRef": {"key": "value"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("ref"), makeValue(R"("key")")},
                   FAILURE(customRefExpected("ref"))),
        /*** The key is matched literally: a dot is part of the member name, not a path separator ***/
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"a.b": "dotted", "a": {"b": "nested"}})"), makeValue(R"("a.b")")},
                   SUCCESS(literalArgsExpected(makeEvent(R"({"target": "dotted"})")))),
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"a": {"b": "nested"}})"), makeValue(R"("a.b")")},
                   FAILURE(literalArgsExpected())),
        TransformT(R"({"ref": "a.b", "obj": {"a.b": "dotted"}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("obj"), makeRef("ref")},
                   SUCCESS(customRefExpected(
                       makeEvent(R"({"ref": "a.b", "obj": {"a.b": "dotted"}, "target": "dotted"})"), "ref", "obj"))),
        TransformT(R"({"ref": "a.b", "obj": {"a": {"b": "nested"}}})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeRef("obj"), makeRef("ref")},
                   FAILURE(customRefExpected("ref", "obj"))),
        // The key '.' is a member name, not the whole object
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({".": "dot", "x": 1})"), makeValue(R"(".")")},
                   SUCCESS(literalArgsExpected(makeEvent(R"({"target": "dot"})")))),
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"x": 1})"), makeValue(R"(".")")},
                   FAILURE(literalArgsExpected())),
        // The JSON pointer characters of the key are escaped
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"a/b": "slash", "a~b": "tilde"})"), makeValue(R"("a/b")")},
                   SUCCESS(literalArgsExpected(makeEvent(R"({"target": "slash"})")))),
        TransformT(R"({})",
                   opBuilderHelperGetValue,
                   "target",
                   {makeValue(R"({"a/b": "slash", "a~b": "tilde"})"), makeValue(R"("a~b")")},
                   SUCCESS(literalArgsExpected(makeEvent(R"({"target": "tilde"})")))),
        /*** lookup_merge(object, key) ***/
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
                   FAILURE(customRefExpected("ref1", "ref2", "target"))),
        TransformT(R"({"ref1": "key", "ref2": {"key": {"a": "value"}}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1")},
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                               .WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.a")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT(R"({"ref": "key"})",
                   opBuilderHelperMergeValue,
                   ".",
                   {makeValue(R"({"key": {"key1": "value"}})"), makeRef("ref")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref", ".")(mocks);
                           return makeEvent(R"({"key1": "value", "ref": "key"})");
                       })),
        /*** A literal key ***/
        TransformT(R"({"target": {"k0": "v0"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"k1": "v1"}})"), makeValue(R"("key")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"target": {"k0": "v0", "k1": "v1"}})"), "target"))),
        TransformT(
            R"({"obj": {"key": {"k1": "v1"}}, "target": {"k0": "v0"}})",
            opBuilderHelperMergeValue,
            "target",
            {makeRef("obj"), makeValue(R"("key")")},
            SUCCESS(customRefExpected(
                makeEvent(R"({"obj": {"key": {"k1": "v1"}}, "target": {"k0": "v0", "k1": "v1"}})"), "obj", "target"))),
        TransformT(R"({"target": {"k0": "v0"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"k1": "v1"}})"), makeValue(R"("other")")},
                   FAILURE(customRefExpected("target"))),
        /*** A shallow merge replaces a nested object; with 'deep' it is merged ***/
        TransformT(
            R"({"ref": "key", "target": {"k0": "v0", "nested": {"k1": "v1"}}})",
            opBuilderHelperMergeValue,
            "target",
            {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeRef("ref")},
            SUCCESS(customRefExpected(
                makeEvent(R"({"ref": "key", "target": {"k0": "v0", "nested": {"k2": "v2"}}})"), "ref", "target"))),
        /*** lookup_merge(object, key, 'deep') ***/
        TransformT(R"({"ref": "key", "target": {"k0": "v0", "nested": {"k1": "v1"}}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeRef("ref"), makeValue(R"("deep")")},
                   SUCCESS(customRefExpected(
                       makeEvent(R"({"ref": "key", "target": {"k0": "v0", "nested": {"k1": "v1", "k2": "v2"}}})"),
                       "ref",
                       "target"))),
        TransformT(R"({"ref": "key-not-exits", "target": {"k0": "v0", "nested": {"k1": "v1"}}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeRef("ref"), makeValue(R"("deep")")},
                   FAILURE(customRefExpected("ref", "target"))),
        TransformT(
            R"({"ref1": "key", "ref2": {"key": {"nested": {"k0": "v0"}}}, "target": {"nested": {"k1": "v1"}}})",
            opBuilderHelperMergeValue,
            "target",
            {makeRef("ref2"), makeRef("ref1"), makeValue(R"("deep")")},
            SUCCESS(customRefExpected(
                makeEvent(
                    R"({"ref1": "key", "ref2": {"key": {"nested": {"k0": "v0"}}}, "target": {"nested": {"k1": "v1", "k0": "v0"}}})"),
                "ref1",
                "ref2",
                "target"))),
        TransformT(R"({"target": {"nested": {"k1": "v1"}}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeValue(R"("key")"), makeValue(R"("deep")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"target": {"nested": {"k1": "v1", "k2": "v2"}}})"),
                                             "target"))),
        TransformT(R"({"ref1": "key", "ref2": {"key": {"a": "value"}}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeRef("ref2"), makeRef("ref1"), makeValue(R"("deep")")},
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target")))
                               .WillOnce(testing::Return(true));
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("target.a")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        TransformT(R"({"key1": {"key2": "value"}, "ref": "key"})",
                   opBuilderHelperMergeValue,
                   ".",
                   {makeValue(R"({"key": {"key1": {"key3": "value"}}})"), makeRef("ref"), makeValue(R"("deep")")},
                   SUCCESS(
                       [](const BuildersMocks& mocks)
                       {
                           customRefExpected("ref", ".")(mocks);
                           return makeEvent(R"({"key1": {"key2": "value", "key3": "value"}, "ref": "key"})");
                       })),
        /*** A nested type conflict in deep mode fails and leaves the target untouched ***/
        TransformT(
            R"({"ref": "key", "target": {"nested": "x"}})",
            opBuilderHelperMergeValue,
            "target",
            {makeValue(R"({"key": {"other": "v", "nested": {"k2": "v2"}}})"), makeRef("ref"), makeValue(R"("deep")")},
            FAILURE(customRefExpected("ref", "target"))),
        TransformT(R"({"ref": "key", "target": {"nested": "x"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeRef("ref"), makeValue(R"("deep")")},
                   FAILURE(customRefExpected("ref", "target"))),
        TransformT(R"({"ref": "key", "target": {"nested": ["x"]}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeRef("ref"), makeValue(R"("deep")")},
                   FAILURE(customRefExpected("ref", "target"))),
        // Without 'deep' the same source replaces the conflicting member
        TransformT(R"({"ref": "key", "target": {"nested": "x"}})",
                   opBuilderHelperMergeValue,
                   "target",
                   {makeValue(R"({"key": {"nested": {"k2": "v2"}}})"), makeRef("ref")},
                   SUCCESS(customRefExpected(
                       makeEvent(R"({"ref": "key", "target": {"nested": {"k2": "v2"}}})"), "ref", "target")))),
    testNameFormatter<TransformOperationTest>("ObjectGet"));
} // namespace transformoperatestest

#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{
auto customRef()
{
    return [](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));
        return None {};
    };
}

auto typeArrayRef(bool isArray)
{
    return [=](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.schema, isArray(DotPath("ref"))).WillOnce(testing::Return(isArray));
        return None {};
    };
}

auto typeRef(schemf::Type sType)
{
    return [=](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.schema, getType(DotPath("ref"))).WillRepeatedly(testing::Return(sType));
        return None {};
    };
}
} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        /*** Match Value ***/
        FilterT({}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeValue("1")}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeValue(R"("str")")}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperMatchValue, SUCCESS()),
        FilterT({makeValue(R"([1,2])")}, opfilter::opBuilderHelperMatchValue, SUCCESS()),
        FilterT({makeValue(R"(["1","2"])")}, opfilter::opBuilderHelperMatchValue, SUCCESS()),
        FilterT({makeValue(R"([])"), makeValue(R"([])")}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeValue("null")}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchValue, SUCCESS(customRef())),
        FilterT({makeRef("ref"), makeRef("ref")}, opfilter::opBuilderHelperMatchValue, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchValue, SUCCESS(typeArrayRef(true))),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchValue, FAILURE(typeArrayRef(false))),
        /*** Match key ***/
        FilterT({}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeValue("1")}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeValue(R"("str")")}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperMatchKey, SUCCESS()),
        FilterT({makeValue(R"({})"), makeValue(R"({})")}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeValue("null")}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchKey, SUCCESS(customRef())),
        FilterT({makeRef("ref"), makeRef("ref")}, opfilter::opBuilderHelperMatchKey, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchKey, SUCCESS(typeRef(schemf::Type::OBJECT))),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchKey, FAILURE(typeRef(schemf::Type::TEXT))),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperMatchKey, FAILURE(typeRef(schemf::Type::DOUBLE)))),
    testNameFormatter<FilterBuilderTest>("Match"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        /*** Match Value ***/
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeValue(R"(["value"])")},
                SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperMatchValue, "target", {makeValue(R"([1])")}, SUCCESS()),
        FilterT(
            R"({"target": true})", opfilter::opBuilderHelperMatchValue, "target", {makeValue(R"([true])")}, SUCCESS()),
        FilterT(R"({"target": []})", opfilter::opBuilderHelperMatchValue, "target", {makeValue(R"([[]])")}, SUCCESS()),
        FilterT(R"({"target": {}})", opfilter::opBuilderHelperMatchValue, "target", {makeValue(R"([{}])")}, SUCCESS()),
        FilterT(
            R"({"target": null})", opfilter::opBuilderHelperMatchValue, "target", {makeValue(R"([null])")}, SUCCESS()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeValue(R"(["a", "value"])")},
                SUCCESS()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeValue(R"(["an", "other", "value"])")},
                SUCCESS()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperMatchValue,
                "notTarget",
                {makeValue(R"(["value"])")},
                FAILURE()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeValue(R"(["val0", "val1"])")},
                FAILURE()),
        FilterT(R"({"target": "value", "ref": ["value"]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": 1, "ref": [1]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": true, "ref": [true]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": [], "ref": [[]]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": {}, "ref": [{}]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": null, "ref": [null]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": ["a", "value"]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": ["an", "other", "value"]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": ["value"]})",
                opfilter::opBuilderHelperMatchValue,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": ["val0", "val1"]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "notRef": ["value"]})",
                opfilter::opBuilderHelperMatchValue,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        /*** Match key ***/
        FilterT(R"({"target": "key"})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeValue(R"({"key": "value"})")},
                SUCCESS()),
        FilterT(R"({"target": "key"})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeValue(R"({"k": "v", "key": "value"})")},
                SUCCESS()),
        FilterT(R"({"target": "key"})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeValue(R"({"k0": "v0", "k1": "v1", "key": "value"})")},
                SUCCESS()),
        FilterT(R"({"target": "key"})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeValue(R"({"k0": "v0", "k1": "v1", "k2": "v2"})")},
                FAILURE()),
        FilterT(R"({"target": "key"})",
                opfilter::opBuilderHelperMatchKey,
                "notTarget",
                {makeValue(R"({"key": "value"})")},
                FAILURE()),
        FilterT(R"({"target": "key", "ref": {"key": "value"}})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "key", "ref": {"k": "v", "key": "value"}})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "key", "ref": {"k0": "v0", "k1": "v1", "key": "value"}})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "key", "ref": {"k0": "v0", "k1": "v1", "k2": "v2"}})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "key", "ref": {"key": "value"}})",
                opfilter::opBuilderHelperMatchKey,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "key", "notRef": {"key": "value"}})",
                opfilter::opBuilderHelperMatchKey,
                "target",
                {makeRef("ref")},
                FAILURE(customRef()))),
    testNameFormatter<FilterOperationTest>("Match"));
} // namespace filteroperatestest

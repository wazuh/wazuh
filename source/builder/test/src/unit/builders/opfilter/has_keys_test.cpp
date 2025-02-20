#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{

auto customRefExpected()
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto jTypeArrayRefExpected(json::Json::Type jType, bool isArray = true)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, isArray(DotPath("ref"))).WillOnce(testing::Return(isArray));
        if (isArray)
        {
            EXPECT_CALL(*mocks.validator, getJsonType(DotPath("ref"))).WillOnce(testing::Return(jType));
        }
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
        // Wrong arguments number
        FilterT({}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"("string")"), makeValue(R"("string")")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE()),
        // Value
        FilterT({makeValue(R"("string")")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"(2)")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"(1.2)")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"([1, 2, 3])")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"({"a": 1, "b": 2})")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperKeysExistInList, FAILURE()),
        FilterT({makeValue(R"(["ts", "host", "wazuh"])")}, opfilter::opBuilderHelperKeysExistInList, SUCCESS()),
        // Reference
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE(jTypeArrayRefExpected(json::Json::Type::Number))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE(jTypeArrayRefExpected(json::Json::Type::Boolean))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE(jTypeArrayRefExpected(json::Json::Type::Array))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE(jTypeArrayRefExpected(json::Json::Type::Object))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE(jTypeArrayRefExpected(json::Json::Type::Null))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                SUCCESS(jTypeArrayRefExpected(json::Json::Type::String))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperKeysExistInList,
                FAILURE(jTypeArrayRefExpected(json::Json::Type::String, false))),
        FilterT({makeRef("ref"), makeRef("ref")}, opfilter::opBuilderHelperKeysExistInList, FAILURE())),
    testNameFormatter<FilterBuilderTest>("HasKeys"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        // Value cases
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({"target": 1})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({"target": 1.2})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({"target": true})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({"target": ["t", "a", "r", "g", "e", "t"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["v", "a", "l", "u", "e"])")},
                FAILURE()),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["key"])")},
                FAILURE()),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["key", "key_not_found"])")},
                FAILURE()),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["key", "other_key"])")},
                SUCCESS()),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeValue(R"(["key", "other_key", "more_key"])")},
                SUCCESS()),
        // Reference cases
        FilterT(R"({"target": "value", "ref": ["r", "e", "f"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "value", "ref": ["r", "e", "f"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": ["r", "e", "f"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1.2, "ref": ["r", "e", "f"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": false, "ref": ["r", "e", "f"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": ["t", "a", "r", "g", "e", "t"], "ref": ["r", "e", "f"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": [1, 2, 3]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": [1.2, 2.5, 3.9]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": [true, false, true]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(
            R"({"target": {"key": "value", "other_key": "other_value"}, "ref": [{"key": "value"}, {"other_key": "value"}]})",
            opfilter::opBuilderHelperKeysExistInList,
            "target",
            {makeRef("ref")},
            FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": "key"})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": 1})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": 1.2})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": false})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": {"key": "value"}})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": ["key"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": ["key", "key_not_found"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": ["key", "other_key"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": {"key": "value", "other_key": "other_value"}, "ref": ["key", "other_key", "more_key"]})",
                opfilter::opBuilderHelperKeysExistInList,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected()))),
    testNameFormatter<FilterOperationTest>("HasKeys"));

} // namespace filteroperatestest

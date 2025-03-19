/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 18, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "reflectiveJson_test.hpp"
#include "reflectiveJson.hpp"

void ReflectiveJsonTest::SetUp() {};
void ReflectiveJsonTest::TearDown() {};

template<typename TData>
struct TestData final
{
    std::string fieldOne;
    int fieldTwo;
    TData fieldThree;

    REFLECTABLE(MAKE_FIELD("fieldOne", &TestData::fieldOne),
                MAKE_FIELD("fieldTwo", &TestData::fieldTwo),
                MAKE_FIELD("fieldThree", &TestData::fieldThree));
};

TEST_F(ReflectiveJsonTest, EmptyMapReturnsEmptyBraces)
{
    std::unordered_map<std::string, std::string> emptyMap;
    std::string result = jsonFieldToString(emptyMap);
    EXPECT_EQ(result, "{}");
}

TEST_F(ReflectiveJsonTest, SingleStringEntry)
{
    std::unordered_map<std::string, std::string> map {{"key", "value"}};
    std::string result = jsonFieldToString(map);
    EXPECT_EQ(result, R"({"key":"value"})");
}

TEST_F(ReflectiveJsonTest, MultipleStringEntries)
{
    std::unordered_map<std::string, std::string> map {{"key1", "value1"}, {"key2", "value2"}};
    std::string result = jsonFieldToString(map);

    // Order of fields in an unordered_map is not guaranteed.
    // We check for both valid permutations.
    bool validPermutation1 = (result == R"({"key1":"value1","key2":"value2"})");
    bool validPermutation2 = (result == R"({"key2":"value2","key1":"value1"})");
    EXPECT_TRUE(validPermutation1 || validPermutation2);
}

TEST_F(ReflectiveJsonTest, NumericValues)
{
    std::unordered_map<std::string, int> map {{"intVal", 42}, {"zeroVal", 0}, {"negativeVal", -10}};
    std::string result = jsonFieldToString(map);

    // Possible orders in the JSON:
    // {"intVal":42,"zeroVal":0,"negativeVal":-10}
    // {"intVal":42,"negativeVal":-10,"zeroVal":0}
    // etc.
    // We check presence of all fields with correct values.
    EXPECT_NE(result.find(R"("intVal":42)"), std::string::npos);
    EXPECT_NE(result.find(R"("zeroVal":0)"), std::string::npos);
    EXPECT_NE(result.find(R"("negativeVal":-10)"), std::string::npos);
    EXPECT_EQ(result.front(), '{');
    EXPECT_EQ(result.back(), '}');
}

TEST_F(ReflectiveJsonTest, NestedMap)
{
    std::unordered_map<std::string, std::unordered_map<std::string, int>> map {{"outerKey", {{"innerKey", 123}}}};
    std::string result = jsonFieldToString(map);

    EXPECT_EQ(result, "{\"outerKey\":{\"innerKey\":123}}");
}

TEST_F(ReflectiveJsonTest, EscapedStringValue)
{
    std::unordered_map<std::string, std::string> map {{"key", "He said \"Hello\""}};

    std::string result = jsonFieldToString(map);

    EXPECT_NE(result.find(R"("key":"He said \"Hello\"")"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerialization)
{
    TestData<float> obj;
    obj.fieldOne = "001";
    obj.fieldTwo = 30;
    obj.fieldThree = 1.3;

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":"001")"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":30)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":1.3)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, NestedStructSerialization)
{
    struct NestedData
    {
        std::string innerField;
        int innerValue;

        REFLECTABLE(MAKE_FIELD("innerField", &NestedData::innerField),
                    MAKE_FIELD("innerValue", &NestedData::innerValue));
    };

    TestData<NestedData> obj;
    obj.fieldOne = "Outer";
    obj.fieldTwo = 2;
    obj.fieldThree.innerField = "Inner";
    obj.fieldThree.innerValue = 42;

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":"Outer")"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":{"innerField":"Inner","innerValue":42})"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithEmptyFields)
{
    TestData<std::string_view> obj;
    obj.fieldOne = "";
    obj.fieldTwo = 0;
    obj.fieldThree = "";

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_EQ(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":0)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithQuotes)
{
    TestData<float> obj;
    obj.fieldOne = "\"001\"";
    obj.fieldTwo = 30;
    obj.fieldThree = 1.3;

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":"\"001\"")"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":30)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":1.3)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BooleanValues)
{
    TestData<bool> obj;
    obj.fieldOne = "\"001\"";
    obj.fieldTwo = 30;
    obj.fieldThree = true;

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":"\"001\"")"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":30)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":true)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, SpecialCharactersInKeysAndValues)
{
    std::unordered_map<std::string, std::string> map {{"newline", "Line1\nLine2"},
                                                      {"tabbed", "A\tB\tC"},
                                                      {"backslash", "Path\\To\\File"},
                                                      {"quote", "\"Quoted text\""}};
    std::string result = jsonFieldToString(map);

    EXPECT_NE(result.find(R"("newline":"Line1\nLine2")"), std::string::npos);
    EXPECT_NE(result.find(R"("tabbed":"A\tB\tC")"), std::string::npos);
    EXPECT_NE(result.find(R"("backslash":"Path\\To\\File")"), std::string::npos);
    EXPECT_NE(result.find(R"("quote":"\"Quoted text\"")"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, NumericBufferZeroing)
{
    struct NumericTest
    {
        int firstValue;
        double secondValue;
        int thirdValue;

        REFLECTABLE(MAKE_FIELD("firstValue", &NumericTest::firstValue),
                    MAKE_FIELD("secondValue", &NumericTest::secondValue),
                    MAKE_FIELD("thirdValue", &NumericTest::thirdValue));
    };

    NumericTest obj;
    obj.firstValue = 42;
    obj.secondValue = 3.1415;
    obj.thirdValue = -99;

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_NE(json.find(R"("firstValue":42)"), std::string::npos);
    EXPECT_NE(json.find(R"("secondValue":3.1415)"), std::string::npos);
    EXPECT_NE(json.find(R"("thirdValue":-99)"), std::string::npos);

    // Validate JSON starts and ends correctly. If buffer is not zeroed, there will be garbage characters.
    EXPECT_EQ(json.front(), '{');
    EXPECT_EQ(json.back(), '}');
}

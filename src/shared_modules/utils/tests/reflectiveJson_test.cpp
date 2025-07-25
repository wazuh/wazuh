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
#if defined(HAS_TO_CHARS_FLOAT) && HAS_TO_CHARS_FLOAT == true
#include "json.hpp"
#include "reflectiveJson.hpp"

void ReflectiveJsonTest::SetUp() {};
void ReflectiveJsonTest::TearDown() {};

template<typename TData>
struct TestData final
{
    std::string fieldOne;
    int64_t fieldTwo;
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

    // Validate JSON structure using nlohmann::json
    nlohmann::json parsedJson;
    ASSERT_NO_THROW(parsedJson = nlohmann::json::parse(result)) << "Invalid JSON output: " << result;

    // Parse expected JSON into nlohmann::json
    nlohmann::json expectedJson = map;

    // Compare structured JSON objects instead of raw strings
    EXPECT_EQ(parsedJson, expectedJson) << "JSON mismatch!\nExpected: " << expectedJson.dump(4)
                                        << "\nActual: " << parsedJson.dump(4);
}

TEST_F(ReflectiveJsonTest, NumericValues)
{
    std::unordered_map<std::string, int> map {{"intVal", 42}, {"zeroVal", 0}, {"negativeVal", -10}};

    std::string result = jsonFieldToString(map);

    // Validate JSON structure using nlohmann::json
    nlohmann::json parsedJson;
    ASSERT_NO_THROW(parsedJson = nlohmann::json::parse(result)) << "Invalid JSON output: " << result;

    // Parse expected JSON into nlohmann::json
    nlohmann::json expectedJson = map;

    // Compare structured JSON objects instead of raw strings
    EXPECT_EQ(parsedJson, expectedJson) << "JSON mismatch!\nExpected: " << expectedJson.dump(4)
                                        << "\nActual: " << parsedJson.dump(4);
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
    TestData<double> obj;
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
        int64_t innerValue;

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

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithEmptyFieldsDoNotIgnore)
{
    TestData<std::string_view> obj;
    obj.fieldOne = "";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = "";

    std::string json;
    serializeToJSON<TestData<std::string_view>, false>(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":-9223372036854775808)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithEmptyFieldsDoNotIgnoreComplex)
{
    struct NestedData
    {
        std::string innerField;
        int64_t innerValue;

        REFLECTABLE(MAKE_FIELD("innerField", &NestedData::innerField),
                    MAKE_FIELD("innerValue", &NestedData::innerValue));
    };

    TestData<NestedData> obj;
    obj.fieldOne = "";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree.innerField = "";
    obj.fieldThree.innerValue = DEFAULT_INT_VALUE;

    std::string json;
    serializeToJSON<TestData<NestedData>, false>(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":-9223372036854775808)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":{"innerField":"","innerValue":-9223372036854775808})"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithEmptyFieldsDoIgnoreComplex)
{
    struct NestedData
    {
        std::string innerField;
        int64_t innerValue;

        REFLECTABLE(MAKE_FIELD("innerField", &NestedData::innerField),
                    MAKE_FIELD("innerValue", &NestedData::innerValue));
    };

    TestData<NestedData> obj;
    obj.fieldOne = "";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree.innerField = "";
    obj.fieldThree.innerValue = DEFAULT_INT_VALUE;

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_EQ(json, "{}");
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithWhiteSpace)
{
    TestData<std::string_view> obj;
    obj.fieldOne = " ";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = " ";

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_EQ(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldTwo":0)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithWhiteSpaceDoNotIgnore)
{
    TestData<std::string_view> obj;
    obj.fieldOne = " ";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = " ";

    std::string json;
    serializeToJSON<TestData<std::string_view>, true, false>(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldTwo":-9223372036854775808)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithEmptyAndWhiteSpace)
{
    TestData<std::string_view> obj;
    obj.fieldOne = "";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = " ";

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_EQ(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldTwo":0)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithEmptyAndWhiteSpaceDoNotIgnore)
{
    TestData<std::string_view> obj;
    obj.fieldOne = "";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = " ";

    std::string json;
    serializeToJSON<TestData<std::string_view>, false, false>(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldTwo":-9223372036854775808)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithIntegerEmptyFields)
{
    TestData<std::string_view> obj;
    obj.fieldOne = "hello";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = "world";

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_NE(json.find(R"("fieldOne":"hello")"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldTwo":)"), std::string::npos);
    EXPECT_NE(json.find(R"("fieldThree":"world")"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithAllEmptyFields)
{
    TestData<std::string_view> obj;
    obj.fieldOne = "";
    obj.fieldTwo = DEFAULT_INT_VALUE;
    obj.fieldThree = " ";

    std::string json;
    serializeToJSON(obj, json);

    EXPECT_EQ(json.find(R"("fieldOne":)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldTwo":)"), std::string::npos);
    EXPECT_EQ(json.find(R"("fieldThree":)"), std::string::npos);
}

TEST_F(ReflectiveJsonTest, BasicStructSerializationWithQuotes)
{
    TestData<double> obj;
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

TEST_F(ReflectiveJsonTest, FullEscapeTableCoverage)
{
    std::unordered_map<std::string, std::string> map {
        {"quote", "\"Quoted text\""},
        {"backslash", "Path\\To\\File"},
        {"backspace", "Text\bBack"},
        {"formfeed", "Page\fBreak"},
        {"newline", "Line1\nLine2"},
        {"carriage_return", "Line\rReset"},
        {"unicode_text", "NetLock_Arany_=Class_Gold=_Főtanúsítvány.pem"},
        {"tabbed", "A\tB\tC"},
        {"ET", "🏠"} // Unicode emoji
    };

    std::string result = jsonFieldToString(map);

    // Validate JSON structure using nlohmann::json
    nlohmann::json parsedJson;
    ASSERT_NO_THROW(parsedJson = nlohmann::json::parse(result)) << "Invalid JSON output: " << result;

    // Parse expected JSON into nlohmann::json
    nlohmann::json expectedJson = map;

    // Compare structured JSON objects instead of raw strings
    EXPECT_EQ(parsedJson, expectedJson) << "JSON mismatch!\nExpected: " << expectedJson.dump(4)
                                        << "\nActual: " << parsedJson.dump(4);
}

TEST_F(ReflectiveJsonTest, NumericBufferZeroing)
{
    struct NumericTest
    {
        int64_t firstValue;
        double secondValue;
        int64_t thirdValue;

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
#endif

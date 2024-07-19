/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015-2023, Wazuh Inc.
 * October 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#include "jsonArrayParser_test.hpp"
#include "json.hpp"
#include "jsonArrayParser.hpp"
#include "gtest/gtest.h"
#include <queue>

/**
 * @brief Parse an array with simple objects
 *
 */
TEST_F(JsonArrayParserTest, ArrayWithSimpleObjects)
{
    // Setup the input data
    const auto testData {R"(
    {"cves_array":
            [
                {"cve":"CVE-2005-AAAA"},
                {"cve":"CVE-2008-AAAA"},
                {"cve":"CVE-2012-AAAA"}
            ]
    }
    )"};
    const auto testArrayPointer {"/cves_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ArrayWithSimpleObjects.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"({"cve":"CVE-2005-AAAA"})"_json);
    expectedItems.push(R"({"cve":"CVE-2008-AAAA"})"_json);
    expectedItems.push(R"({"cve":"CVE-2012-AAAA"})"_json);
    auto currentId = 1;
    // This callback will validate the extracted items
    auto callback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);

        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());
}

/**
 * @brief The target array is empty. The item callback should not be called.
 *
 */
TEST_F(JsonArrayParserTest, ArrayIsEmpty)
{
    // Setup the input data
    const auto testData {R"(
    {
        "test_array": []
    }
    )"};
    const auto testArrayPointer {"/test_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ArrayIsEmpty.json"};
    createTestFile(testData, testFilepath);

    // The array is empty, this callback should never be called
    auto callback = [](nlohmann::json&& /*item*/, const size_t /*itemId*/)
    {
        // Execution should never reach here
        EXPECT_TRUE(false) << "The callback should not have been called.";

        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer));
}

/**
 * @brief The target array does not exist. Expect exception.
 *
 */
TEST_F(JsonArrayParserTest, ArrayIsNotFound)
{
    // Setup the input data
    const auto testData {R"(
    {"test_array":
            []
    }
    )"};

    // The given array pointer does not exist on the json object
    const auto testArrayPointer {"/wrong_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ArrayIsNotFound.json"};
    createTestFile(testData, testFilepath);

    // The array does not exist, this callback should never be called
    auto callback = [](nlohmann::json&& /*item*/, const size_t /*itemId*/)
    {
        // Execution should never reach here
        EXPECT_TRUE(false) << "The callback should not have been called.";

        return true;
    };

    // Parse the JSON array and expect an exception
    ASSERT_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer), std::runtime_error);
}

/**
 * @brief The target array inside a parent array does not exist. Expect exception.
 *
 */
TEST_F(JsonArrayParserTest, TargetArrayInsideArrayIsNotFound)
{
    // Setup the input data
    const auto testData {R"(
    [
        ["the", "first", "array"],
        ["the", "second", "array"]
    ]
    )"};

    // The given array pointer does not exist on the json object. The top array only has items index 0 and 1.
    const auto testArrayPointer {"/2"_json_pointer};
    const auto testFilepath {m_testFolder / "TargetArrayInsideArrayIsNotFound.json"};
    createTestFile(testData, testFilepath);

    // The array does not exist, this callback should never be called
    auto callback = [](nlohmann::json&& /*item*/, const size_t /*itemId*/)
    {
        // Execution should never reach here
        EXPECT_TRUE(false) << "The callback should not have been called.";

        return true;
    };

    // Parse the JSON array and expect an exception
    ASSERT_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer), std::runtime_error);
}

/**
 * @brief Parse an array with values of different types.
 *
 */
TEST_F(JsonArrayParserTest, ArrayWithDifferentTypeValues)
{
    // Setup the input data
    const auto testData {R"(
    {"test_array":
            [
             1,"some string",false,true,["nested","array"],null,-34,0.56,{"key":"value"}
            ]
    }
    )"};
    const auto testArrayPointer {"/test_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ArrayWithDifferentTypeValues.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"(1)"_json);
    expectedItems.push(R"("some string")"_json);
    expectedItems.push(R"(false)"_json);
    expectedItems.push(R"(true)"_json);
    expectedItems.push(R"(["nested","array"])"_json);
    expectedItems.push(R"(null)"_json);
    expectedItems.push(R"(-34)"_json);
    expectedItems.push(R"(0.56)"_json);
    expectedItems.push(R"({"key":"value"})"_json);

    auto currentId = 1;

    // This callback will validate the extracted items
    auto callback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);
        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());
}

/**
 * @brief Parse an array with more complex objects.
 *
 */
TEST_F(JsonArrayParserTest, ArrayWithComplexObjects)
{
    // Setup the input data
    const auto testData {R"(
    {
        "test_array":[
            {"cve":{"id":"CVE-2005-AAAA","data":{"key":"value1"},"nestedArray":[3,4,5]}},
            {"cve":{"id":"CVE-2006-AAAA","data":{"key":"value2"},"nestedArray":[6,7,8]}},
            {"cve":{"id":"CVE-2007-AAAA","data":{"key":"value3"},"nestedArray":[9,10,11]}}
            ]
    }
    )"};
    const auto testArrayPointer {"/test_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ArrayWithComplexObjects.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"({"cve":{"id":"CVE-2005-AAAA","data":{"key":"value1"},"nestedArray":[3,4,5]}})"_json);
    expectedItems.push(R"({"cve":{"id":"CVE-2006-AAAA","data":{"key":"value2"},"nestedArray":[6,7,8]}})"_json);
    expectedItems.push(R"({"cve":{"id":"CVE-2007-AAAA","data":{"key":"value3"},"nestedArray":[9,10,11]}})"_json);

    auto currentId = 1;

    // This callback will validate the extracted items
    auto callback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);
        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());
}

/**
 * @brief Check that the JSON body is received correctly.
 *
 */
TEST_F(JsonArrayParserTest, ReceiveJsonBody)
{
    // Setup the input data
    const auto testData {R"(
    {
        "some_key":"some_value",
        "cves_array":
            [
                {"cve":"CVE-2005-AAAA"},
                {"cve":"CVE-2008-AAAA"}
            ],
        "some_object":{"key":"value"}
    }
    )"};
    const auto testArrayPointer {"/cves_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ReceiveJsonBody.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"({"cve":"CVE-2005-AAAA"})"_json);
    expectedItems.push(R"({"cve":"CVE-2008-AAAA"})"_json);

    // Set the expected json body, this is the original json without the array items
    const auto expectedBody = R"(
        {
            "some_key": "some_value",
            "cves_array": [],
            "some_object": {
                "key": "value"
            }
        }
        )"_json;
    const auto expectedBodyCallbackCount {1};
    auto bodyCallbackCount {0};

    auto currentId = 1;

    // This callback will validate the extracted items
    auto itemCallback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);
        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // This callback will validate the extracted json body
    auto bodyCallback = [&expectedBody, &bodyCallbackCount](nlohmann::json&& item)
    {
        // Check that the body equals the expected one.
        EXPECT_EQ(expectedBody, item);

        // Increment the counter of this callback
        ++bodyCallbackCount;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, itemCallback, testArrayPointer, bodyCallback));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());

    // The body callback should have been called only once
    EXPECT_EQ(bodyCallbackCount, expectedBodyCallbackCount);
}

/**
 * @brief Check that the JSON body is received correctly when the top level is an array.
 *
 */
TEST_F(JsonArrayParserTest, ReceiveJsonBodyTopLevelArray)
{
    // Setup the input data
    const auto testData {R"(
    [
        ["the", "first", "array"],
        ["the", "second", "array"],
        ["the", "target","array"]
    ]
    )"};
    const auto testArrayPointer {"/2"_json_pointer};
    const auto testFilepath {m_testFolder / "ReceiveJsonBodyTopLevelArray.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"("the")"_json);
    expectedItems.push(R"("target")"_json);
    expectedItems.push(R"("array")"_json);

    // Set the expected json body, this is the original json without the array items
    const auto expectedBody = R"(
        [
            ["the", "first", "array"],
            ["the", "second", "array"],
            []
        ]
    )"_json;
    auto bodyCallbackCount {0};

    auto currentId = 1;

    // This callback will validate the extracted items
    auto itemCallback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);
        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // This callback will validate the extracted json body
    auto bodyCallback = [&expectedBody, &bodyCallbackCount](nlohmann::json&& item)
    {
        // Check that the body equals the expected one.
        EXPECT_EQ(expectedBody, item);

        // Increment the counter of this callback
        ++bodyCallbackCount;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, itemCallback, testArrayPointer, bodyCallback));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());

    // The body callback should have been called only once
    EXPECT_EQ(bodyCallbackCount, 1);
}

/**
 * @brief Parse an array that is at the top level of the JSON object
 *
 */
TEST_F(JsonArrayParserTest, TopLevelArray)
{
    // Setup the input data
    const auto testData {R"(
    [
        {"cve":"CVE-2005-AAAA"},
        {"cve":"CVE-2008-AAAA"},
        {"cve":"CVE-2012-AAAA"}
    ]
    )"};
    const auto testFilepath {m_testFolder / "TopLevelArray.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"({"cve":"CVE-2005-AAAA"})"_json);
    expectedItems.push(R"({"cve":"CVE-2008-AAAA"})"_json);
    expectedItems.push(R"({"cve":"CVE-2012-AAAA"})"_json);

    auto currentId = 1;

    // This callback will validate the extracted items
    auto callback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);
        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());
}

/**
 * @brief Parse an array that is located on a deeper level.
 *
 */
TEST_F(JsonArrayParserTest, ComplexJsonPointer)
{
    // Setup the input data
    const auto testData {R"(
        {
        "some_key": "some_value",
        "one_array":
            [
                {"some_object": {"key": "value"}},
                {"cves_array":
                    [
                        {"cve": "CVE-2005-AAAA"},
                        {"cve": "CVE-2008-AAAA"}
                    ]
                }
            ]
        }
    )"};
    const auto testArrayPointer {"/one_array/1/cves_array"_json_pointer};
    const auto testFilepath {m_testFolder / "ComplexJsonPointer.json"};
    createTestFile(testData, testFilepath);

    // Set the expected items
    std::queue<nlohmann::json> expectedItems;
    expectedItems.push(R"({"cve":"CVE-2005-AAAA"})"_json);
    expectedItems.push(R"({"cve":"CVE-2008-AAAA"})"_json);

    // Set the expected json body, this is the original json without the array items
    const auto expectedBody = R"(
    {
        "some_key": "some_value",
        "one_array":
            [
                {"some_object": {"key": "value"}},
                {"cves_array":
                    []
                }
            ]
    }
    )"_json;
    auto bodyCallbackCount {0};

    auto currentId = 1;

    // This callback will validate the extracted items
    auto itemCallback = [&](nlohmann::json&& item, const size_t itemId)
    {
        // Check that the current item equals the one at the front of the expected queue
        EXPECT_EQ(expectedItems.front(), item);

        // Check that the item id is correct
        EXPECT_EQ(itemId, currentId);
        ++currentId;

        // Remove item from queue
        expectedItems.pop();

        return true;
    };

    // This callback will validate the extracted json body
    auto bodyCallback = [&expectedBody, &bodyCallbackCount](nlohmann::json&& item)
    {
        // Check that the body equals the expected one.
        EXPECT_EQ(expectedBody, item);

        // Increment the counter of this callback
        ++bodyCallbackCount;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, itemCallback, testArrayPointer, bodyCallback));

    // At the end of the processing the expected queue must be empty
    EXPECT_TRUE(expectedItems.empty());

    // The body callback should have been called only once
    EXPECT_EQ(bodyCallbackCount, 1);
}

/**
 * @brief Stop the parsing when the callback returns false, the items are objects.
 *
 */
TEST_F(JsonArrayParserTest, StopParsingWithObjectItems)
{
    // Setup the input data
    const auto testData {R"(
    {"cves_array":
            [
                {"cve":"CVE-2005-AAAA"},
                {"cve":"CVE-2008-AAAA"},
                {"cve":"CVE-2012-AAAA"},
                {"cve":"CVE-2016-AAAA"},
                {"cve":"CVE-2022-AAAA"}
            ]
    }
    )"};
    const auto testArrayPointer {"/cves_array"_json_pointer};
    const auto testFilepath {m_testFolder / "StopParsingWithObjectItems.json"};
    createTestFile(testData, testFilepath);

    constexpr auto targetCve {"CVE-2012-AAAA"};
    constexpr auto expectedItemsCallbacksCount {3};

    auto itemCallbackCounter {0};

    // This callback will return false and stop the parsing when the item with "CVE-2012-AAAA" is received
    auto callback = [&itemCallbackCounter](nlohmann::json&& item, const size_t /*itemId*/)
    {
        // Increment callback counter
        ++itemCallbackCounter;

        if (item.at("cve") == targetCve)
        {
            // Item found, return false to stop the parsing
            return false;
        }
        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer));

    // At the end of the processing the callback must have been called three times because the parsing was stopped after
    // the third item
    EXPECT_EQ(itemCallbackCounter, expectedItemsCallbacksCount);
}

/**
 * @brief Stop the parsing when the callback returns false, the items are simple values.
 *
 */
TEST_F(JsonArrayParserTest, StopParsingWitValueItems)
{
    // Setup the input data
    const auto testData {R"(
    {"cves_array":
            [
                1,
                2,
                3
            ]
    }
    )"};
    const auto testArrayPointer {"/cves_array"_json_pointer};
    const auto testFilepath {m_testFolder / "StopParsingWitValueItems.json"};
    createTestFile(testData, testFilepath);

    constexpr auto targetItem {2};
    constexpr auto expectedItemCallbackCount {2};

    auto itemCallbackCounter {0};

    // This callback will return false and stop the parsing when two items are received
    auto callback = [&itemCallbackCounter](nlohmann::json&& item, const size_t /*itemId*/)
    {
        // Increment callback counter
        ++itemCallbackCounter;

        if (item == targetItem)
        {
            // Item found, return false to stop the parsing
            return false;
        }
        return true;
    };

    // Parse the JSON array
    ASSERT_NO_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer));

    // At the end of the processing the callback must have been called two times because the parsing was stopped after
    // the second item
    EXPECT_EQ(itemCallbackCounter, expectedItemCallbackCount);
}

/**
 * @brief The JSON file has wrong syntax. Expect exception.
 *
 */
TEST_F(JsonArrayParserTest, JsonWithWrongSyntax)
{
    // Setup the input data
    // testData has wrong syntax: extra comma
    const auto testData {R"(
    {"test_array":
            ["1","2","3"]
            ,
    }
    )"};
    const auto testArrayPointer {"/test_array"_json_pointer};
    const auto testFilepath {m_testFolder / "JsonWithWrongSyntax.json"};
    createTestFile(testData, testFilepath);

    auto callback = [](nlohmann::json&& /*item*/, const size_t /*itemId*/)
    {
        return true;
    };

    // Parse the JSON array and expect an exception
    ASSERT_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer), nlohmann::detail::parse_error);
}

/**
 * @brief The JSON file does not exist. Expect exception.
 *
 */
TEST_F(JsonArrayParserTest, InexistentFile)
{
    // Setup the input data
    const auto testArrayPointer {"/test_array"_json_pointer};
    const auto testFilepath {m_testFolder / "inexistent.json"};

    auto callback = [](nlohmann::json&& /*item*/, const size_t /*itemId*/)
    {
        return true;
    };

    // Start the parse and expect an exception
    ASSERT_THROW(JsonArray::parse(testFilepath, callback, testArrayPointer), std::runtime_error);
}

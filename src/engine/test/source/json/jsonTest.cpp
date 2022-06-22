#include "json.hpp"
#include "gtest/gtest.h"

#include <iostream>
#include <string>

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

using namespace std;
using namespace json;

TEST(JsonBase, InitializeDefault)
{
    ASSERT_NO_THROW(Json doc;);
    ASSERT_NO_THROW(Json doc {};);
}

TEST(JsonBase, InitializeCopy)
{
    Json doc;
    ASSERT_NO_THROW(Json doc2 {doc};);
}

TEST(JsonBase, AssignmentCopy)
{
    Json doc;
    ASSERT_NO_THROW(Json doc2 = doc;);
}

TEST(JsonBase, InitializeJsonString)
{
    ASSERT_NO_THROW(Json doc {"{\"key\":\"value\"}"};);
    ASSERT_NO_THROW(Json doc {"{}"};);
    ASSERT_THROW(Json doc {"{\"key\":\"value\"}}"};, std::runtime_error);
}

// TODO: Add more use cases, and add cases once operators and arrays are implemented.
TEST(JsonStatic, FormatJsonPath)
{
    auto dotPath = "key.value";
    std::string pointerPath;
    ASSERT_NO_THROW(pointerPath = Json::formatJsonPath(dotPath););
    ASSERT_EQ(pointerPath, "/key/value");

    dotPath = ".key.value";
    ASSERT_NO_THROW(pointerPath = Json::formatJsonPath(dotPath););
    ASSERT_EQ(pointerPath, "/key/value");
}

TEST(JsonBuildtime, Size)
{
    // Empty object
    Json emptyObj {"{}"};
    ASSERT_EQ(emptyObj.size(), 0);

    // Empty array
    Json emptyArr {"[]"};
    ASSERT_EQ(emptyArr.size(), 0);

    // Object
    Json obj {"{\"key\":\"value\"}"};
    ASSERT_EQ(obj.size(), 1);

    // Array
    Json arr {"[\"value\"]"};
    ASSERT_EQ(arr.size(), 1);

    // None object or array
    Json none {"null"};
    ASSERT_THROW(none.size(), std::runtime_error);
}

TEST(JsonBuildtime, Null)
{
    Json none {"null"};
    ASSERT_TRUE(none.isNull());
}

TEST(JsonBuildtime, Bool)
{
    Json trueVal {"true"};
    ASSERT_TRUE(trueVal.isBool());
    ASSERT_TRUE(trueVal.getBool());

    Json falseVal {"false"};
    ASSERT_TRUE(falseVal.isBool());
    ASSERT_FALSE(falseVal.getBool());
}

TEST(JsonBuildtime, Number)
{
    Json integer {"123"};
    ASSERT_TRUE(integer.isNumber());
    ASSERT_EQ(integer.getInt(), 123);

    Json real {"123.456"};
    ASSERT_TRUE(real.isNumber());
    ASSERT_EQ(real.getDouble(), 123.456);
}

TEST(JsonBuildtime, String)
{
    Json str {"\"value\""};
    ASSERT_TRUE(str.isString());
    ASSERT_EQ(str.getString(), "value");
}

TEST(JsonBuildtime, Array)
{
    Json arr {"[\"value\"]"};
    ASSERT_TRUE(arr.isArray());
    ASSERT_EQ(arr.size(), 1);
    ASSERT_EQ(arr.getArray()[0].getString(), "value");
}

TEST(JsonBuildtime, Object)
{
    Json obj {"{\"key\":\"value\"}"};
    ASSERT_TRUE(obj.isObject());
    ASSERT_EQ(obj.size(), 1);
    ASSERT_EQ(std::get<0>(obj.getObject()[0]), "key");
    ASSERT_EQ(std::get<1>(obj.getObject()[0]).getString(), "value");
}

TEST(JsonRuntime, InitializeCopyMove)
{
    Json doc;
    ASSERT_NO_THROW(Json doc2 {std::move(doc)};);
}

TEST(JsonRuntime, AssignmentCopyMove)
{
    Json doc;
    ASSERT_NO_THROW(Json doc2 = std::move(doc););
}

TEST(JsonRuntime, Exists)
{
    // One level deep
    Json doc {"{\"key\":\"value\"}"};
    ASSERT_TRUE(doc.exists("/key"));
    ASSERT_FALSE(doc.exists("/key2"));
    ASSERT_THROW(doc.exists("key"), std::runtime_error);
    ASSERT_THROW(doc.exists(".key"), std::runtime_error);

    // Two levels deep
    doc = Json {"{\"key\":{\"key2\":\"value\"}}"};
    ASSERT_TRUE(doc.exists("/key/key2"));
    ASSERT_FALSE(doc.exists("/key/key3"));
    ASSERT_THROW(doc.exists("key/key2/key3"), std::runtime_error);
    ASSERT_THROW(doc.exists(".key/key2/key3"), std::runtime_error);

    // Three levels deep
    doc = Json {"{\"key\":{\"key2\":{\"key3\":\"value\"}}}"};
    ASSERT_TRUE(doc.exists("/key/key2/key3"));
    ASSERT_FALSE(doc.exists("/key/key2/key4"));
    ASSERT_THROW(doc.exists("key/key2/key3/key4"), std::runtime_error);
    ASSERT_THROW(doc.exists(".key/key2/key3/key4"), std::runtime_error);
}

TEST(JsonRuntime, EqualsValue)
{
    Json doc {R"({
        "object": {
            "key": "value"
        },
        "array": [
            "value"
        ],
        "int": 123,
        "real": 123.456,
        "boolT": true,
        "boolF": false,
        "null": null,
        "string": "value",
        "nested": {
            "object": {
                "key": "value"
            },
            "array": [
                "value"
            ],
            "int": 123,
            "real": 123.456,
            "boolT": true,
            "boolF": false,
            "null": null,
            "string": "value"
        }
    })"};

    Json value;

    // Object
    value = Json {"{\"key\":\"value\"}"};
    ASSERT_TRUE(doc.equals("/object", value));
    ASSERT_TRUE(doc.equals("/nested/object", value));

    // Array
    value = Json {"[\"value\"]"};
    ASSERT_TRUE(doc.equals("/array", value));
    ASSERT_TRUE(doc.equals("/nested/array", value));

    // Integer
    value = Json {"123"};
    ASSERT_TRUE(doc.equals("/int", value));
    ASSERT_TRUE(doc.equals("/nested/int", value));

    // Real
    value = Json {"123.456"};
    ASSERT_TRUE(doc.equals("/real", value));
    ASSERT_TRUE(doc.equals("/nested/real", value));

    // Boolean
    value = Json {"true"};
    ASSERT_TRUE(doc.equals("/boolT", value));
    ASSERT_TRUE(doc.equals("/nested/boolT", value));

    value = Json {"false"};
    ASSERT_TRUE(doc.equals("/boolF", value));
    ASSERT_TRUE(doc.equals("/nested/boolF", value));

    // Null
    value = Json {"null"};
    ASSERT_TRUE(doc.equals("/null", value));
    ASSERT_TRUE(doc.equals("/nested/null", value));

    // String
    value = Json {"\"value\""};
    ASSERT_TRUE(doc.equals("/string", value));

    // Wrong pointer
    ASSERT_THROW(doc.equals("object/key", value), std::runtime_error);

    // Non-existent pointer
    ASSERT_FALSE(doc.equals("/non-existent", value));

    // False cases
    // TODO: Iterative comparation of all types
    value = Json {"\"value2\""};
    ASSERT_FALSE(doc.equals("/object", value));
    ASSERT_FALSE(doc.equals("/array", value));
    ASSERT_FALSE(doc.equals("/int", value));
    ASSERT_FALSE(doc.equals("/real", value));
    ASSERT_FALSE(doc.equals("/boolT", value));
    ASSERT_FALSE(doc.equals("/boolF", value));
    ASSERT_FALSE(doc.equals("/null", value));
    ASSERT_FALSE(doc.equals("/string", value));
    ASSERT_FALSE(doc.equals("/nested/object", value));
}

TEST(JsonRuntime, EqualsReference)
{
    Json doc {R"({
        "object": {
            "key": "value"
        },
        "array": [
            "value"
        ],
        "int": 123,
        "real": 123.456,
        "boolT": true,
        "boolF": false,
        "null": null,
        "string": "value",
        "nested": {
            "object": {
                "key": "value"
            },
            "array": [
                "value"
            ],
            "int": 123,
            "real": 123.456,
            "boolT": true,
            "boolF": false,
            "null": null,
            "string": "value"
        }
    })"};

    Json value;

    // Object
    ASSERT_TRUE(doc.equals("/object", "/nested/object"));
    ASSERT_TRUE(doc.equals("/nested/object", "/object"));

    // Array
    ASSERT_TRUE(doc.equals("/array", "/nested/array"));
    ASSERT_TRUE(doc.equals("/nested/array", "/array"));

    // Integer
    ASSERT_TRUE(doc.equals("/int", "/nested/int"));
    ASSERT_TRUE(doc.equals("/nested/int", "/int"));

    // Real
    ASSERT_TRUE(doc.equals("/real", "/nested/real"));
    ASSERT_TRUE(doc.equals("/nested/real", "/real"));

    // Boolean
    ASSERT_TRUE(doc.equals("/boolT", "/nested/boolT"));
    ASSERT_TRUE(doc.equals("/nested/boolT", "/boolT"));

    ASSERT_TRUE(doc.equals("/boolF", "/nested/boolF"));
    ASSERT_TRUE(doc.equals("/nested/boolF", "/boolF"));

    // Null
    ASSERT_TRUE(doc.equals("/null", "/nested/null"));
    ASSERT_TRUE(doc.equals("/nested/null", "/null"));

    // String
    ASSERT_TRUE(doc.equals("/string", "/nested/string"));
    ASSERT_TRUE(doc.equals("/nested/string", "/string"));

    // Wrong pointer
    ASSERT_THROW(doc.equals("object/key", "/nested/object"), std::runtime_error);
    ASSERT_THROW(doc.equals("/object", "object/key"), std::runtime_error);

    // Non-existent pointer
    ASSERT_FALSE(doc.equals("/nonexistent", "/nested/object"));
    ASSERT_FALSE(doc.equals("/nested/object", "/nonexistent"));

    // False cases
    // TODO: Iterative comparation of all types
    ASSERT_FALSE(doc.equals("/object", "/array"));
    ASSERT_FALSE(doc.equals("/array", "/object"));
    ASSERT_FALSE(doc.equals("/int", "/real"));
    ASSERT_FALSE(doc.equals("/real", "/int"));
    ASSERT_FALSE(doc.equals("/boolT", "/boolF"));
    ASSERT_FALSE(doc.equals("/boolF", "/boolT"));
    ASSERT_FALSE(doc.equals("/null", "/string"));
    ASSERT_FALSE(doc.equals("/string", "/null"));
    ASSERT_FALSE(doc.equals("/object", "/nested/int"));
    ASSERT_FALSE(doc.equals("/nested/int", "/object"));
}

TEST(JsonRuntime, SetValue)
{
    Json expected {R"({
        "object": {
        "key": "value"
        },
        "nested": {
            "object": {
                "key": "value"
            },
            "array": [
                "value"
            ],
            "int": 123,
            "real": 123.456,
            "boolT": true,
            "boolF": false,
            "null": null,
            "string": "value"
        },
        "array": [
            "value"
        ],
        "int": 123,
        "real": 123.456,
        "boolT": true,
        "boolF": false,
        "null": null,
        "string": "value"
    })"};
    Json doc {"{}"};

    // Object
    doc.set("/object", Json {"{\"key\": \"value\"}"});
    ASSERT_TRUE(doc.equals("/object", Json {"{\"key\": \"value\"}"}));
    doc.set("/nested/object", Json {"{\"key\": \"value\"}"});
    ASSERT_TRUE(doc.equals("/nested/object", Json {"{\"key\": \"value\"}"}));

    // Array
    doc.set("/array", Json {"[\"value\"]"});
    ASSERT_TRUE(doc.equals("/array", Json {"[\"value\"]"}));
    doc.set("/nested/array", Json {"[\"value\"]"});
    ASSERT_TRUE(doc.equals("/nested/array", Json {"[\"value\"]"}));

    // Integer
    doc.set("/int", Json {"123"});
    ASSERT_TRUE(doc.equals("/int", Json {"123"}));
    doc.set("/nested/int", Json {"123"});
    ASSERT_TRUE(doc.equals("/nested/int", Json {"123"}));

    // Real
    doc.set("/real", Json {"123.456"});
    ASSERT_TRUE(doc.equals("/real", Json {"123.456"}));
    doc.set("/nested/real", Json {"123.456"});
    ASSERT_TRUE(doc.equals("/nested/real", Json {"123.456"}));

    // Boolean
    doc.set("/boolT", Json {"true"});
    ASSERT_TRUE(doc.equals("/boolT", Json {"true"}));
    doc.set("/nested/boolT", Json {"true"});
    ASSERT_TRUE(doc.equals("/nested/boolT", Json {"true"}));

    doc.set("/boolF", Json {"false"});
    ASSERT_TRUE(doc.equals("/boolF", Json {"false"}));
    doc.set("/nested/boolF", Json {"false"});
    ASSERT_TRUE(doc.equals("/nested/boolF", Json {"false"}));

    // Null
    doc.set("/null", Json {"null"});
    ASSERT_TRUE(doc.equals("/null", Json {"null"}));
    doc.set("/nested/null", Json {"null"});
    ASSERT_TRUE(doc.equals("/nested/null", Json {"null"}));

    // String
    doc.set("/string", Json {"\"value\""});
    ASSERT_TRUE(doc.equals("/string", Json {"\"value\""}));
    doc.set("/nested/string", Json {"\"value\""});
    ASSERT_TRUE(doc.equals("/nested/string", Json {"\"value\""}));

    // Expected
    ASSERT_EQ(expected.str(), doc.str());

    // Wrong pointer
    ASSERT_THROW(doc.set("object/key", Json {"\"value\""}), std::runtime_error);
}

TEST(JsonRuntime, SetReference)
{
    Json doc1 {R"({
        "nested": {
            "object": {
                "key": "value"
            },
            "array": [
                "value"
            ],
            "int": 123,
            "real": 123.456,
            "boolT": true,
            "boolF": false,
            "null": null,
            "string": "value"
        }
    })"};

    Json doc2 {R"({
        "nested": {},
        "object": {
            "key": "value"
        },
        "array": [
            "value"
        ],
        "int": 123,
        "real": 123.456,
        "boolT": true,
        "boolF": false,
        "null": null,
        "string": "value"
    })"};

    // Object
    doc1.set("/object", "/nested/object");
    ASSERT_TRUE(doc1.equals("/object", "/nested/object"));
    doc2.set("/nested/object", "/object");
    ASSERT_TRUE(doc2.equals("/nested/object", "/object"));

    // Array
    doc1.set("/array", "/nested/array");
    ASSERT_TRUE(doc1.equals("/array", "/nested/array"));
    doc2.set("/nested/array", "/array");
    ASSERT_TRUE(doc2.equals("/nested/array", "/array"));

    // Integer
    doc1.set("/int", "/nested/int");
    ASSERT_TRUE(doc1.equals("/int", "/nested/int"));
    doc2.set("/nested/int", "/int");
    ASSERT_TRUE(doc2.equals("/nested/int", "/int"));

    // Real
    doc1.set("/real", "/nested/real");
    ASSERT_TRUE(doc1.equals("/real", "/nested/real"));
    doc2.set("/nested/real", "/real");
    ASSERT_TRUE(doc2.equals("/nested/real", "/real"));

    // Boolean
    doc1.set("/boolT", "/nested/boolT");
    ASSERT_TRUE(doc1.equals("/boolT", "/nested/boolT"));
    doc2.set("/nested/boolT", "/boolT");
    ASSERT_TRUE(doc2.equals("/nested/boolT", "/boolT"));

    doc1.set("/boolF", "/nested/boolF");
    ASSERT_TRUE(doc1.equals("/boolF", "/nested/boolF"));
    doc2.set("/nested/boolF", "/boolF");
    ASSERT_TRUE(doc2.equals("/nested/boolF", "/boolF"));

    // Null
    doc1.set("/null", "/nested/null");
    ASSERT_TRUE(doc1.equals("/null", "/nested/null"));
    doc2.set("/nested/null", "/null");
    ASSERT_TRUE(doc2.equals("/nested/null", "/null"));

    // String
    doc1.set("/string", "/nested/string");
    ASSERT_TRUE(doc1.equals("/string", "/nested/string"));
    doc2.set("/nested/string", "/string");
    ASSERT_TRUE(doc2.equals("/nested/string", "/string"));

    // Expected
    ASSERT_EQ(doc1.str(), doc2.str());

    // Wrong pointer
    ASSERT_THROW(doc1.set("object/key", "/nested/object"), std::runtime_error);
    ASSERT_THROW(doc1.set("/object", "object/key"), std::runtime_error);

    // Reference to non-existent object, maps to null
    doc1.set("/object", "/non-existent");
    ASSERT_TRUE(doc1.equals("/object", Json {"null"}));
}

TEST(JsonRuntime, PrettyStr)
{
    std::string expected = R"({
    "nested": {
        "object": {
            "key": "value"
        },
        "array": [
            "value"
        ],
        "int": 123,
        "real": 123.456,
        "boolT": true,
        "boolF": false,
        "null": null,
        "string": "value"
    }
})";

    Json doc {expected.c_str()};

    ASSERT_EQ(expected, doc.prettyStr());
}

TEST(JsonRuntime, Str)
{
    std::string expected = "{\"nested\":{\"object\":{\"key\":\"value\"},\"array\":["
                           "\"value\"],\"int\":123,\"real\":123.456,\"boolT\":true,"
                           "\"boolF\":false,\"null\":null,\"string\":\"value\"}}";

    Json doc {expected.c_str()};

    ASSERT_EQ(expected, doc.str());
}

TEST(JsonSets, setObject)
{
    Json doc {R"({
        "one": 1,
        "two": 2,
        "three": 3
    })"};

    Json obj;

    auto docObj = doc.getObject();
    ASSERT_NO_THROW(obj.setObject(docObj));
    ASSERT_EQ(doc.str(), obj.str());
}

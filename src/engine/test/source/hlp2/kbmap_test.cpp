#include <gtest/gtest.h>
#include "run_test.hpp"
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <string>
#include <vector>

TEST(HLP2, KVParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc {in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(f1=v1 f2=v2 f3=v3###)", true, "###", Options {"=", " ", "'", ""}, fn(R"({"f1":"v1","f2":"v2","f3":"v3"})"), 17},
        TestCase {R"(key1=Value1 Key2=Value2-dummy)", true, "-dummy", Options {"=", " ", "'", ""}, fn(R"({"key1":"Value1","Key2":"Value2"})"), 23},
        // fail if parser do not reach stop or end
        TestCase {R"(key1=Value1 Key2=)", false, {}, Options {"=", " ", "'", ""}, fn(R"({"key1":"Value1","Key2":null})"), 18},
        TestCase {R"(key1=Value1 Key2)", false, {}, Options {"=", " ", "'", ""}, fn(R"({"key1":"Value1"})"), 11},
        TestCase {R"(key1=Value1 =Value2)", false, {}, Options {"=", " ", "'", ""}, fn(R"({"key1":"Value1"})"), 19},
        TestCase {R"(=Value1 =Value2)", false, {}, Options {"=", " ", "'", ""}, fn(R"({"key1":"Value1"})"), 19},
//      // should we support multi chars sep or delim?
//      // TestCase {R"(key1: Value1 Key2: Value2 hi!)", true, {}, Options {":", " ", "'", ""}, fn(R"({"key1":"Value1","Key2":"Value2"})"), 19},
        TestCase {R"(keyX=valueX)", false, {}, Options {":", ",", "'", ""}, fn(R"({"keyX":"valueX"})"), 19},
        TestCase {R"(keyX=valueX)", true, {}, Options {"=", ",", "'", ""}, fn(R"({"keyX":"valueX"})"), 11},
        TestCase {R"(keyX|valueX)", true, {}, Options {"|", ",", "'", ""}, fn(R"({"keyX":"valueX"})"), 11},
        // fail if parser do not reach stop or end
        TestCase {R"(keyX:"valueX;";)", false, {}, Options {":", ";", "\"", ""}, fn(R"({"keyX":"valueX;"})"), 14},
        // fail if parser do not reach stop or end
        TestCase {R"(key1= key2="" key3=)", false, {}, Options {"=", " ", "\"", "\\"}, fn(R"({"key1":null,"key2":null,"key3":null})"), 20},
        TestCase {R"(: ;)", false, {}, Options {":", " ", "'", ""}, fn(R"({})"), 0},
        TestCase {R"(: valueX;)", false, {}, Options {":", " ", "'", ""}, fn(R"({})"), 0},
        TestCase {R"(: valueX)", false, {}, Options {":", " ", "'", ""}, fn(R"({})"), 0},
        TestCase {R"(:valueX)", false, {}, Options {":", " ", "'", ""}, fn(R"({})"), 0},
        TestCase {R"(key1:value1,:value2)", false, {}, Options {":", ",", "'", ""}, fn(R"({})"), 0},
        TestCase {R"(key1:value1,key2:value2,:value3)", false, {}, Options {":", ",", "'", ""}, fn(R"({})"), 0},
        // best effort parsing, index returns up to the most complete kv pair or
        // fail if parser do not reach stop or end
        TestCase {R"(key1:value1,key2:value2,value3)", false, {}, Options {":", ",", "'", ""}, fn(R"({"key1":"value1","key2":"value2"})"), 23},
        TestCase {R"(key1:value1,key2:value2,:)", false, {}, Options {":", ",", "'", ""}, fn(R"({})"), 0},
        // different escape char
        TestCase {R"("key1":"value\"1",key2:value2)", true, {}, Options {":", ",", "\"", "\\"}, fn(R"({"key1": "value\"1", "key2": "value2"})"), 29},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getKVParser);
    }
}

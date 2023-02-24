#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <string>
#include <vector>

TEST(KVParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc {in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(f1=v1 f2=v2 f3=v3)",
                  true,
                  {""},
                  Options {"=", " ", "\"", "\\"},
                  fn(R"({"f1":"v1","f2":"v2","f3":"v3"})"),
                  17},
        TestCase {R"(f1=v1 f2=v2 f3=v3###)",
                  true,
                  {"###"},
                  Options {"=", " ", "'", "\\"},
                  fn(R"({"f1":"v1","f2":"v2","f3":"v3"})"),
                  17},
        TestCase {R"(key1=Value1 Key2=Value2-dummy)",
                  true,
                  {"-dummy"},
                  Options {"=", " ", "'", "\\"},
                  fn(R"({"key1":"Value1","Key2":"Value2"})"),
                  23},
        // fail if parser do not reach stop or end
        TestCase {R"(key1=Value1 Key2=)",
                  true,
                  {""},
                  Options {"=", " ", "'", "\\"},
                  fn(R"({"key1":"Value1","Key2":null})"),
                  17},
        TestCase {R"(key1=Value1 Key2)",
                  false,
                  {""},
                  Options {"=", " ", "'", "\\"},
                  fn(R"({"key1":"Value1"})"),
                  11},
        TestCase {R"(key1=Value1 =Value2)",
                  false,
                  {},
                  Options {"=", " ", "'", "\\"},
                  fn(R"({"key1":"Value1"})"),
                  19},
        TestCase {R"(=Value1 =Value2)",
                  false,
                  {},
                  Options {"=", " ", "'", "\\"},
                  fn(R"({"key1":"Value1"})"),
                  19},
        //      // should we support multi chars sep or delim?
        //      // TestCase {R"(key1: Value1 Key2: Value2 hi!)", true, {}, Options {":", "
        //      ", "'", "\\"}, fn(R"({"key1":"Value1","Key2":"Value2"})"), 19},
        TestCase {R"(keyX=valueX)",
                  false,
                  {},
                  Options {":", ",", "'", "\\"},
                  fn(R"({"keyX":"valueX"})"),
                  19},
        TestCase {R"(keyX=valueX)",
                  true,
                  {},
                  Options {"=", ",", "'", "\\"},
                  fn(R"({"keyX":"valueX"})"),
                  11},
        TestCase {R"(keyX|valueX)",
                  true,
                  {},
                  Options {"|", ",", "'", "\\"},
                  fn(R"({"keyX":"valueX"})"),
                  11},
        // fail if parser do not reach stop or end
        TestCase {R"(keyX:"valueX;";)",
                  false,
                  {},
                  Options {":", ";", "\"", "\\"},
                  fn(R"({"keyX":"valueX;"})"),
                  14},
        // fail if parser do not reach stop or end
        TestCase {R"(key1= key2="" key3=)",
                  true,
                  {},
                  Options {"=", " ", "\"", "\\"},
                  fn(R"({"key1":null,"key2":null,"key3":null})"),
                  19},
        TestCase {R"(: ;)", false, {}, Options {":", " ", "'", "\\"}, fn(R"({})"), 0},
        TestCase {R"(: valueX;)", false, {}, Options {":", " ", "'", "\\"}, fn(R"({})"), 0},
        TestCase {R"(: valueX)", false, {}, Options {":", " ", "'", "\\"}, fn(R"({})"), 0},
        TestCase {R"(:valueX)", false, {}, Options {":", " ", "'", "\\"}, fn(R"({})"), 0},
        TestCase {R"(key1:value1,:value2)",
                  false,
                  {},
                  Options {":", ",", "'", "\\"},
                  fn(R"({})"),
                  0},
        TestCase {R"(key1:value1,key2:value2,:value3)",
                  false,
                  {},
                  Options {":", ",", "'", "\\"},
                  fn(R"({})"),
                  0},
        // best effort parsing, index returns up to the most complete kv pair or
        // fail if parser do not reach stop or end
        TestCase {R"(key1:value1,key2:value2,value3)",
                  false,
                  {},
                  Options {":", ",", "'", "\\"},
                  fn(R"({"key1":"value1","key2":"value2"})"),
                  23},
        TestCase {R"(key1:value1,key2:value2,:)",
                  false,
                  {},
                  Options {":", ",", "'", "\\"},
                  fn(R"({})"),
                  0},
        // different escape char
        TestCase {R"("key1":"value\"1",key2:value2)",
                  true,
                  {},
                  Options {":", ",", "\"", "\\"},
                  fn(R"({"key1": "value\"1", "key2": "value2"})"),
                  29},
        // Audit example message
        TestCase {R"("key1":"value1,notkey2:notvalue2","key2":"value2")",
                  true,
                  {},
                  Options {":", ",", "\"", "\\"},
                  fn(R"({"key1": "value1,notkey2:notvalue2", "key2": "value2"})"),
                  strlen(R"("key1":"value1,notkey2:notvalue2","key2":"value2")")},
        TestCase {R"("key1":"\"value1\"","key2":"value2")",
                  true,
                  {},
                  Options {":", ",", "\"", "\\"},
                  fn(R"({"key1": "\"value1\"", "key2": "value2"})"),
                  strlen(R"("key1":"\"value1\"","key2":"value2")")},
        TestCase {
            R"(pid=6969 subj=system_u:system_r:virtd_t:s0-s0:c0.c1023 msg='virt=kvm vm=\"rhel-work3\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe="/usr/sbin/someexe" terminal=? res=success')",
            true,
            {},
            Options {"=", " ", "'", "\\"},
            fn(R"({"pid":6969,"subj":"system_u:system_r:virtd_t:s0-s0:c0.c1023","msg":"virt=kvm vm=\\\"rhel-work3\\\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe=\"/usr/sbin/someexe\" terminal=? res=success"})"),
            strlen(
                R"(pid=6969 subj=system_u:system_r:virtd_t:s0-s0:c0.c1023 msg='virt=kvm vm=\"rhel-work3\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe="/usr/sbin/someexe" terminal=? res=success')")},
        TestCase {
            R"(virt=kvm vm=\"rhel-work3\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe="/usr/sbin/someexe" terminal=? res=success)",
            true,
            {},
            Options {"=", " ", "'", "\\"},
            fn(R"({"virt":"kvm","vm":"\\\"rhel-work3\\\"","uuid":"650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf","vm-ctx":"system_u:system_r:svirt_t:s0:c424,c957","exe":"\"/usr/sbin/someexe\"","terminal":"?","res":"success"})"),
            strlen(
                R"(virt=kvm vm=\"rhel-work3\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe="/usr/sbin/someexe" terminal=? res=success)")},
        TestCase {
            "pure_letters=abcdefghijklmnopqrstuvwxyz integer=1234567890 "
            "double=12345.67890 mixed_string_a=1234abcde mixed_string_b=1234.567890abcde",
            true,
            {},
            Options {"=", " ", "'", "\\"},
            fn(R"({"pure_letters":"abcdefghijklmnopqrstuvwxyz","integer":1234567890,"double":12345.67890,"mixed_string_a":"1234abcde","mixed_string_b":"1234.567890abcde"})"),
            strlen("pure_letters=abcdefghijklmnopqrstuvwxyz integer=1234567890 "
                   "double=12345.67890 mixed_string_a=1234abcde "
                   "mixed_string_b=1234.567890abcde")},
        TestCase {R"(key1=value1 key2=value2 key3="")",
                  true,
                  {},
                  Options {"=", " ", "\"", "'"},
                  fn(R"({"key1":"value1","key2":"value2","key3":null})"),
                  31},
        TestCase {R"(key1=value1 key2="" key3=value3)",
                  true,
                  {},
                  Options {"=", " ", "\"", "'"},
                  fn(R"({"key1":"value1","key2":null,"key3":"value3"})"),
                  31},
        TestCase {R"(key1=value1 key2=value2 key3=)",
                  true,
                  {},
                  Options {"=", " ", "\"", "'"},
                  fn(R"({"key1":"value1","key2":"value2","key3":null})"),
                  29},
        TestCase {R"(key1=value1 key2= key3=value3)",
                  true,
                  {},
                  Options {"=", " ", "\"", "'"},
                  fn(R"({"key1":"value1","key2":null,"key3":"value3"})"),
                  29},
        TestCase {R"(key1="value1" key2="123")",
                  true,
                  {},
                  Options {"=", " ", "\"", "'"},
                  fn(R"({"key1":"value1","key2":"123"})"),
                  24},
        TestCase {R"(key1="123" key2=456)",
                  true,
                  {},
                  Options {"=", " ", "\"", "'"},
                  fn(R"({"key1":"123","key2":456})"),
                  19},
        TestCase {R"(key1='value=1',key2=value''2,key3='value,3',key4='value=,''4')",
                  false,
                  {},
                  Options {"=", ",", "'", "'"},
                  fn(R"({"key1":"value=1","key2":"value'2","key3":"value,3","key4":"value=,'4"})"),
                  61}
        };
    for (auto t : testCases)
    {
        runTest(t, hlp::getKVParser);
        runTest(t, hlp::getKVParser, "header", "");
        runTest(t, hlp::getKVParser, "header", "tail");
        runTest(t, hlp::getKVParser, "", "tail");
    }
}

TEST(KVParser, build)
{
        // ok
        ASSERT_NO_THROW(hlp::getKVParser({}, {}, Options {"=", " ", "'", "\\"}));

        // Missing params
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "'"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " "}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"="}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {}), std::runtime_error);
        // Exeeds params
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "'", "\\", ""}), std::runtime_error);

        // Empty params
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"", " ", "'", "\\"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", "", "'", "\\"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "", "\\"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "'", ""}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "'", "\\", ""}), std::runtime_error);

        // Param with more than one char
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"==", " ", "'", "\\"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", "  ", "'", "\\"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "''", "\\"}), std::runtime_error);
        ASSERT_THROW(hlp::getKVParser({}, {""}, Options {"=", " ", "'", "\\\\"}), std::runtime_error);

}

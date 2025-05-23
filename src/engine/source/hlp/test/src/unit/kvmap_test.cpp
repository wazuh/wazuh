#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "kvmapParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(KvBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1", "2"}}),
                                           BuildT(SUCCESS, getKVParser, {NAME, TARGET, {}, {"0", "1", "2", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1", "2", "4", "5"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"00", "1", "2", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "11", "2", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1", "22", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1", "2", "44"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"", "1", "2", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "", "2", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1", "", "4"}}),
                                           BuildT(FAILURE, getKVParser, {NAME, TARGET, {}, {"0", "1", "2", ""}}),
                                           BuildT(SUCCESS, getKVParser, {NAME, TARGET, {}, {"=", " ", "'", "\\"}})));

INSTANTIATE_TEST_SUITE_P(
    KvParse,
    HlpParseTest,
    ::testing::Values(

        ParseT(SUCCESS,
               R"(f1=v1 f2=v2 f3=v3)",
               j(fmt::format(R"({{"{}":{{"f1":"v1","f2":"v2","f3":"v3"}}}})", TARGET.substr(1))),
               17,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(f1=v1 f2=v2 f3=v3###)",
               j(fmt::format(R"({{"{}":{{"f1":"v1","f2":"v2","f3":"v3###"}}}})", TARGET.substr(1))),
               20,
               getKVParser,
               {NAME, TARGET, {"###"}, {"=", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1=Value1 Key2=Value2-dummy)",
               j(fmt::format(R"({{"{}":{{"key1":"Value1","Key2":"Value2-dummy"}}}})", TARGET.substr(1))),
               29,
               getKVParser,
               {NAME, TARGET, {"-dummy"}, {"=", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1=Value1 Key2=)",
               j(fmt::format(R"({{"{}":{{"key1":"Value1","Key2":null}}}})", TARGET.substr(1))),
               17,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1=Value1 Key2)",
               j(fmt::format(R"({{"{}":{{"key1":"Value1"}}}})", TARGET.substr(1))),
               12,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1=Value1 =Value2)",
               j(fmt::format(R"({{"{}":{{"key1":"Value1"}}}})", TARGET.substr(1))),
               12,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(FAILURE, R"(=Value1 =Value2)", {}, 0, getKVParser, {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),
        // should we support multi chars sep or delim?
        // TestCase {R"(key1: Value1 Key2: Value2 hi!)", true, {}, Options {":", "", "'", "\\"},
        // fn(R"({"key1":"Value1","Key2":"Value2"})"), 19},

        ParseT(FAILURE, R"(keyX=valueX)", {}, 0, getKVParser, {NAME, TARGET, {}, {":", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(keyX=valueX)",
               j(fmt::format(R"({{"{}":{{"keyX":"valueX"}}}})", TARGET.substr(1))),
               11,
               getKVParser,
               {NAME, TARGET, {}, {"=", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(keyX|valueX)",
               j(fmt::format(R"({{"{}":{{"keyX":"valueX"}}}})", TARGET.substr(1))),
               11,
               getKVParser,
               {NAME, TARGET, {}, {"|", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(keyX:"valueX;";)",
               j(fmt::format(R"({{"{}":{{"keyX":"valueX;"}}}})", TARGET.substr(1))),
               15,
               getKVParser,
               {NAME, TARGET, {}, {":", ";", "\"", "\\"}}),

        ParseT(SUCCESS,
               R"(key1= key2="" key3=)",
               j(fmt::format(R"({{"{}":{{"key1":null,"key2":null,"key3":null}}}})", TARGET.substr(1))),
               19,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "\\"}}),

        ParseT(FAILURE, R"(: ;)", {}, 0, getKVParser, {NAME, TARGET, {}, {":", " ", "'", "\\"}}),

        ParseT(FAILURE, R"(key:'hi!)", {}, 4, getKVParser, {NAME, TARGET, {}, {":", " ", "'", "\\"}}),

        ParseT(FAILURE, R"(: valueX;)", {}, 0, getKVParser, {NAME, TARGET, {}, {":", " ", "'", "\\"}}),

        ParseT(FAILURE, R"(: valueX)", {}, 0, getKVParser, {NAME, TARGET, {}, {":", " ", "'", "\\"}}),

        ParseT(FAILURE, R"(:valueX)", {}, 0, getKVParser, {NAME, TARGET, {}, {":", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1:value1,:value2)",
               j(fmt::format(R"({{"{}":{{"key1":"value1"}}}})", TARGET.substr(1))),
               12,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1:value1,key2:value2,:value3)",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":"value2"}}}})", TARGET.substr(1))),
               24,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1:value1,key2:value2,value3)",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":"value2"}}}})", TARGET.substr(1))),
               24,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1:value1,key2:value2,:)",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":"value2"}}}})", TARGET.substr(1))),
               24,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"("key1":"value\"1",key2:value2)",
               j(fmt::format(R"({{"{}":{{"key1":"value\"1","key2":"value2"}}}})", TARGET.substr(1))),
               29,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "\"", "\\"}}),

        ParseT(SUCCESS,
               R"("key1":"value1,notkey2:notvalue2","key2":"value2")",
               j(fmt::format(R"({{"{}":{{"key1":"value1,notkey2:notvalue2","key2":"value2"}}}})", TARGET.substr(1))),
               49,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "\"", "\\"}}),

        ParseT(SUCCESS,
               R"("key1":"\"value1\"","key2":"value2")",
               j(fmt::format(R"({{"{}":{{"key1":"\"value1\"","key2":"value2"}}}})", TARGET.substr(1))),
               35,
               getKVParser,
               {NAME, TARGET, {}, {":", ",", "\"", "\\"}}),

        ParseT(
            SUCCESS,
            R"(pid=6969 subj=system_u:system_r:virtd_t:s0-s0:c0.c1023 msg='virt=kvm vm=\"rhel-work3\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe="/usr/sbin/someexe" terminal=? res=success')",
            j(fmt::format(
                R"({{"{}":{{"pid":"6969","subj":"system_u:system_r:virtd_t:s0-s0:c0.c1023","msg":"virt=kvm vm=\\\"rhel-work3\\\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe=\"/usr/sbin/someexe\" terminal=? res=success"}}}})",
                TARGET.substr(1))),
            222,
            getKVParser,
            {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(
            SUCCESS,
            R"(virt=kvm vm=\"rhel-work3\" uuid=650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf vm-ctx=system_u:system_r:svirt_t:s0:c424,c957 exe="/usr/sbin/someexe" terminal=? res=success)",
            j(fmt::format(
                R"({{"{}":{{"virt":"kvm","vm":"\\\"rhel-work3\\\"","uuid":"650c2a3b-2a7d-a7bd-bbc7-aa0069007bbf","vm-ctx":"system_u:system_r:svirt_t:s0:c424,c957","exe":"\"/usr/sbin/someexe\"","terminal":"?","res":"success"}}}})",
                TARGET.substr(1))),
            161,
            getKVParser,
            {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(
            SUCCESS,
            "pure_letters=abcdefghijklmnopqrstuvwxyz integer=1234567890 double=12345.67890 mixed_string_a=1234abcde "
            "mixed_string_b=1234.567890abcde",
            j(fmt::format(
                R"({{"{}":{{"pure_letters":"abcdefghijklmnopqrstuvwxyz","integer":"1234567890","double":"12345.67890","mixed_string_a":"1234abcde","mixed_string_b":"1234.567890abcde"}}}})",
                TARGET.substr(1))),
            134,
            getKVParser,
            {NAME, TARGET, {}, {"=", " ", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1=value1 key2=value2 key3="")",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":"value2","key3":null}}}})", TARGET.substr(1))),
               31,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "'"}}),

        ParseT(SUCCESS,
               R"(key1=value1 key2="" key3=value3)",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":null,"key3":"value3"}}}})", TARGET.substr(1))),
               31,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "'"}}),

        ParseT(SUCCESS,
               R"(key1=value1 key2=value2 key3=)",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":"value2","key3":null}}}})", TARGET.substr(1))),
               29,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "'"}}),

        ParseT(SUCCESS,
               R"(key1=value1 key2= key3=value3)",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":null,"key3":"value3"}}}})", TARGET.substr(1))),
               29,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "'"}}),

        ParseT(SUCCESS,
               R"(key1="value1" key2="123")",
               j(fmt::format(R"({{"{}":{{"key1":"value1","key2":"123"}}}})", TARGET.substr(1))),
               24,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "'"}}),

        ParseT(SUCCESS,
               R"(key1="123" key2=456)",
               j(fmt::format(R"({{"{}": {{"key1":"123","key2":"456"}}}})", TARGET.substr(1))),
               19,
               getKVParser,
               {NAME, TARGET, {}, {"=", " ", "\"", "'"}}),

        ParseT(SUCCESS,
               R"(L=New York City, O=Acme U.S.A., INC., CN=update.acme.com)",
               j(fmt::format(R"({{"{}": {{"L":"New York City"," O":"Acme U.S.A."}}}})", TARGET.substr(1))),
               31,
               getKVParser,
               {NAME, TARGET, {}, {"=", ",", "'", "\\"}}),

        ParseT(SUCCESS,
               R"(key1='value=1',key2=value''2,key3='value,3',key4='value=,''4')",
               j(fmt::format(R"({{"{}": {{"key1":"value=1","key2":"value'2","key3":"value,3","key4":"value=,'4"}}}})",
                             TARGET.substr(1))),
               61,
               getKVParser,
               {NAME, TARGET, {}, {"=", ",", "'", "'"}})));

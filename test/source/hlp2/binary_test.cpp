#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <string>
#include <vector>

TEST(BinaryParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc {in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==",
                  true,
                  {""},
                  Options {},
                  fn(R"("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==")"),
                  strlen("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==")},
        TestCase {"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu",
                  true,
                  {""},
                  Options {},
                  fn(R"("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu")"),
                  strlen("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu")},
        TestCase {"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWE=",
                  true,
                  {""},
                  Options {},
                  fn(R"("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWE=")"),
                  strlen("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWE=")},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
                  true,
                  {""},
                  Options {},
                  fn(R"("SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=")"),
                  strlen("SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=")},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZX=",
                  false,
                  {""},
                  Options {},
                  fn("{}"),
                  0},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZ=",
                  false,
                  {""},
                  Options {},
                  fn("{}"),
                  0},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5l=",
                  false,
                  {""},
                  Options {},
                  fn("{}"),
                  0},
        TestCase {"?GksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
                  false,
                  {""},
                  Options {},
                  fn("{}"),
                  0},
        TestCase {"SGk?IEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
                  false,
                  {""},
                  Options {},
                  fn("{}"),
                  0},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF ZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
                  false,
                  {""},
                  Options {},
                  fn("{}"),
                  0},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5++++",
                  true,
                  {""},
                  Options {},
                  fn("\"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5++++\""),
                  44},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////",
                  true,
                  {""},
                  Options {},
                  fn("\"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////\""),
                  44},
        TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5//// wazuh!",
                  true,
                  {" wazuh!"},
                  Options {},
                  fn("\"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////\""),
                  44},
        //TestCase {"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////+wazuh!",
        //          true,
        //          {"+wazuh!"},
        //          Options {},
        //          fn("\"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////\""),
        //          44},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getBinaryParser);
    }
}

TEST(BinaryParser, build)
{
    // OK
    ASSERT_NO_THROW(hlp::getBinaryParser({}, {}, Options {}));
    // The stop are optional
    ASSERT_NO_THROW(hlp::getBinaryParser({}, {""}, Options {}));

    // Do not allow options
    ASSERT_THROW(hlp::getBinaryParser({}, {}, Options {{""}}), std::runtime_error);
    ASSERT_THROW(hlp::getBinaryParser({}, {}, Options {{"foo"}}), std::runtime_error);
    ASSERT_THROW(hlp::getBinaryParser({}, {}, Options {{"foo", "bar"}}), std::runtime_error);

}

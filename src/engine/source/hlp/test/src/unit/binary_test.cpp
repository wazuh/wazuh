#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "binaryParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(BinaryBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getBinaryParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getBinaryParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    BinaryParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(
            SUCCESS,
            "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIG"
            "luY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3Ry"
            "dWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYX"
            "V0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0"
            "IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIH"
            "F1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==",
            j(fmt::format(
                R"({{"{}": "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg=="}})",
                TARGET.substr(1))),
            596,
            getBinaryParser,
            {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS,
            "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIG"
            "luY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu",
            j(fmt::format(
                R"({{"{}": "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu"}})",
                TARGET.substr(1))),
            164,
            getBinaryParser,
            {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS,
            "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIG"
            "luY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWE=",
            j(fmt::format(
                R"({{"{}": "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWE="}})",
                TARGET.substr(1))),
            164,
            getBinaryParser,
            {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS,
            "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
            j(fmt::format(
                R"({{"{}": "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI="}})",
                TARGET.substr(1))),
            84,
            getBinaryParser,
            {NAME, TARGET, {}, {}}),
        ParseT(FAILURE,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZX=",
               {},
               0,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZ=",
               {},
               0,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5l=",
               {},
               0,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE,
               "?GksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
               {},
               0,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE,
               "SGk?IEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
               {},
               0,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF ZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=",
               {},
               0,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5++++",
               j(fmt::format(R"({{"{}": "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5++++"}})", TARGET.substr(1))),
               44,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////",
               j(fmt::format(R"({{"{}": "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////"}})", TARGET.substr(1))),
               44,
               getBinaryParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5//// left over",
               j(fmt::format(R"({{"{}": "SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGF5////"}})", TARGET.substr(1))),
               44,
               getBinaryParser,
               {NAME, TARGET, {}, {}})));

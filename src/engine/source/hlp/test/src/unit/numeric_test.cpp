#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "textParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(ByteBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getByteParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getByteParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(ByteParse,
                         HlpParseTest,
                         ::testing::Values(ParseT(SUCCESS,
                                                  "42",
                                                  j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                                                  2,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "-42",
                                                  j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                                                  3,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "3.14",
                                                  j(fmt::format(R"({{"{}": 3}})", TARGET.substr(1))),
                                                  4,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "0",
                                                  j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
                                                  1,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                          // Limit values
                                           ParseT(SUCCESS,
                                                  "127",
                                                  j(fmt::format(R"({{"{}": 127}})", TARGET.substr(1))),
                                                  3,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "-128",
                                                  j(fmt::format(R"({{"{}": -128}})", TARGET.substr(1))),
                                                  4,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                          // Out of range values
                                           ParseT(FAILURE, "128", {}, 3, getByteParser, {NAME, TARGET, {}, {}}),
                                           ParseT(FAILURE, "-129", {}, 4, getByteParser, {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "42    ",
                                                  j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                                                  2,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "-42    ",
                                                  j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                                                  3,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "42#####",
                                                  j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                                                  2,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}}),
                                           ParseT(SUCCESS,
                                                  "-42####",
                                                  j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                                                  3,
                                                  getByteParser,
                                                  {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(LongBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getLongParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getLongParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    LongParse,
    HlpParseTest,
    ::testing::Values(ParseT(SUCCESS,
                             "42",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             2,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             3,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "42.9",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             4,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "128",
                             j(fmt::format(R"({{"{}": 128}})", TARGET.substr(1))),
                             3,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-129",
                             j(fmt::format(R"({{"{}": -129}})", TARGET.substr(1))),
                             4,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(FAILURE, "9223372036854775808", {}, 19, getLongParser, {NAME, TARGET, {}, {}}),
                      ParseT(FAILURE, "-9223372036854775809", {}, 20, getLongParser, {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "42    ",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             2,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42    ",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             3,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "42#####",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             2,
                             getLongParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42####",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             3,
                             getLongParser,
                             {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(FloatBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getFloatParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getFloatParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    FloatParse,
    HlpParseTest,
    ::testing::Values(ParseT(SUCCESS,
                             "42",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             2,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "42.0",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             4,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             3,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42.0",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             5,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "128",
                             j(fmt::format(R"({{"{}": 128}})", TARGET.substr(1))),
                             3,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-129",
                             j(fmt::format(R"({{"{}": -129}})", TARGET.substr(1))),
                             4,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "9223372036854775808",
                             j(fmt::format(R"({{"{}": 9223372036854775808}})", TARGET.substr(1))),
                             19,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-9223372036854775809",
                             j(fmt::format(R"({{"{}": -9223372036854775809}})", TARGET.substr(1))),
                             20,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "3.40282e+38",
                             []()
                             {
                                 json::Json expected {};
                                 expected.setFloat(float_t(3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                                 return expected;
                             }(),
                             11,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-3.40282e+38",
                             []()
                             {
                                 json::Json expected {};
                                 expected.setFloat(float_t(-3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                                 return expected;
                             }(),
                             12,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-3.40282e38",
                             []()
                             {
                                 json::Json expected {};
                                 expected.setFloat(float_t(-3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                                 return expected;
                             }(),
                             11,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "42    ",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             2,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42    ",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             3,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "42#####",
                             j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
                             2,
                             getFloatParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "-42####",
                             j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
                             3,
                             getFloatParser,
                             {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(DoubleBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getDoubleParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getDoubleParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    DoubleParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS,
               "42",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42.0",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               4,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42.0",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               5,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "128",
               j(fmt::format(R"({{"{}": 128}})", TARGET.substr(1))),
               3,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-129",
               j(fmt::format(R"({{"{}": -129}})", TARGET.substr(1))),
               4,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "9223372036854775808",
               j(fmt::format(R"({{"{}": 9223372036854775808}})", TARGET.substr(1))),
               19,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-9223372036854775809",
               j(fmt::format(R"({{"{}": -9223372036854775809}})", TARGET.substr(1))),
               20,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "3.40282e+38",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               11,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "10E-1",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(1), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               5,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "10E3",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(10000), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               4,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-3.40282e+38",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(-3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               12,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1.79769e+308",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(1.79769e+308), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               12,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-1.79769e+308",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(-1.79769e+308), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               13,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42    ",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42    ",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42#####",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getDoubleParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42####",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getDoubleParser,
               {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(ScaledFloatBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getScaledFloatParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getScaledFloatParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    ScaledFloatParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS,
               "42",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42.0",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               4,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42.0",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               5,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "128",
               j(fmt::format(R"({{"{}": 128}})", TARGET.substr(1))),
               3,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-129",
               j(fmt::format(R"({{"{}": -129}})", TARGET.substr(1))),
               4,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "9223372036854775808",
               j(fmt::format(R"({{"{}": 9223372036854775808}})", TARGET.substr(1))),
               19,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-9223372036854775809",
               j(fmt::format(R"({{"{}": -9223372036854775809}})", TARGET.substr(1))),
               20,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "10E-1",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(1), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               5,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "3e3",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(3000), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               3,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "3.40282e+38",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               11,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-3.40282e+38",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(-3.40282e+38), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               12,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1.79769e+308",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(1.79769e+308), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               12,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-1.79769e+308",
               []()
               {
                   json::Json expected {};
                   expected.setDouble(double_t(-1.79769e+308), json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               13,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42    ",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42    ",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42#####",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42####",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getScaledFloatParser,
               {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(UnsignedLongBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getUnsignedLongParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getUnsignedLongParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    UnsignedLongParse,
    HlpParseTest,
    ::testing::Values(
        // Mminimum value
        ParseT(SUCCESS,
               "0",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               1,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        // Positive integer
        ParseT(SUCCESS,
               "42",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "12345",
               j(fmt::format(R"({{"{}": 12345}})", TARGET.substr(1))),
               5,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "9223372036854775807",
               j(fmt::format(R"({{"{}": 9223372036854775807}})", TARGET.substr(1))),
               19,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        // Maximum uint64_t value (18,446,744,073,709,551,615)
        ParseT(SUCCESS,
               "18446744073709551615",
               j(fmt::format(R"({{"{}": 18446744073709551615}})", TARGET.substr(1))),
               20,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        // Negative integers
        ParseT(FAILURE, "-1", {}, 2, getUnsignedLongParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-12", {}, 3, getUnsignedLongParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-42", {}, 3, getUnsignedLongParser, {NAME, TARGET, {}, {}}),
        // Decimal values
        ParseT(SUCCESS, "42.0",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               4,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "3.14",
               j(fmt::format(R"({{"{}": 3}})", TARGET.substr(1))),
               4,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "0.5",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               3,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        // Out of range values
        ParseT(FAILURE, "18446744073709551616", {}, 20, getUnsignedLongParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "99999999999999999999", {}, 20, getUnsignedLongParser, {NAME, TARGET, {}, {}}),
        // Trailing spaces
        ParseT(SUCCESS,
               "42    ",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "0     ",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               1,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        // Trailing non-numeric chars
        ParseT(SUCCESS,
               "42#####",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123abc",
               j(fmt::format(R"({{"{}": 123}})", TARGET.substr(1))),
               3,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}}),
        // Leading zeros
        ParseT(SUCCESS,
               "00042",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               5,
               getUnsignedLongParser,
               {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(IntegerBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getIntegerParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getIntegerParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    IntegerParse,
    HlpParseTest,
    ::testing::Values(
        // Minimum value
        ParseT(SUCCESS,
               "-2147483648",
               j(fmt::format(R"({{"{}": -2147483648}})", TARGET.substr(1))),
               11,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Maximum value
        ParseT(SUCCESS,
               "2147483647",
               j(fmt::format(R"({{"{}": 2147483647}})", TARGET.substr(1))),
               10,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Zero
        ParseT(SUCCESS,
               "0",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               1,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Positive integer
        ParseT(SUCCESS,
               "12345",
               j(fmt::format(R"({{"{}": 12345}})", TARGET.substr(1))),
               5,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Negative integer
        ParseT(SUCCESS,
               "-129",
               j(fmt::format(R"({{"{}": -129}})", TARGET.substr(1))),
               4,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Out of range values
        ParseT(FAILURE, "2147483648", {}, 10, getIntegerParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-2147483649", {}, 11, getIntegerParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "9223372036854775807", {}, 19, getIntegerParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-9223372036854775808", {}, 20, getIntegerParser, {NAME, TARGET, {}, {}}),
        // Decimal values
        ParseT(SUCCESS, "42.0",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               4,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "3.14",
               j(fmt::format(R"({{"{}": 3}})", TARGET.substr(1))),
               4,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "-42.5",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               5,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Trailing spaces
        ParseT(SUCCESS,
               "42    ",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42    ",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Trailing non-numeric characters
        ParseT(SUCCESS,
               "42#####",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42####",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123abc",
               j(fmt::format(R"({{"{}": 123}})", TARGET.substr(1))),
               3,
               getIntegerParser,
               {NAME, TARGET, {}, {}}),
        // Leading zeros
        ParseT(SUCCESS,
               "00042",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               5,
               getIntegerParser,
               {NAME, TARGET, {}, {}})
              ));

INSTANTIATE_TEST_SUITE_P(ShortBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getShortParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getShortParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    ShortParse,
    HlpParseTest,
    ::testing::Values(
        // Limit values
        ParseT(SUCCESS,
               "-32768",
               j(fmt::format(R"({{"{}": -32768}})", TARGET.substr(1))),
               6,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "32767",
               j(fmt::format(R"({{"{}": 32767}})", TARGET.substr(1))),
               5,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Zero
        ParseT(SUCCESS,
               "0",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               1,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Positive integers
        ParseT(SUCCESS,
               "42",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "128",
               j(fmt::format(R"({{"{}": 128}})", TARGET.substr(1))),
               3,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1234",
               j(fmt::format(R"({{"{}": 1234}})", TARGET.substr(1))),
               4,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Negative integers
        ParseT(SUCCESS,
               "-1",
               j(fmt::format(R"({{"{}": -1}})", TARGET.substr(1))),
               2,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-129",
               j(fmt::format(R"({{"{}": -129}})", TARGET.substr(1))),
               4,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Out of range values
        ParseT(FAILURE, "32768", {}, 5, getShortParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-32769", {}, 6, getShortParser, {NAME, TARGET, {}, {}}),
        // Decimal values
        ParseT(SUCCESS, "42.0",                j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               4,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "3.14",
               j(fmt::format(R"({{"{}": 3}})", TARGET.substr(1))),
               4,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "-42.5",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               5,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Trailing spaces
        ParseT(SUCCESS,
               "42    ",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42    ",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Trailing non-numeric characters
        ParseT(SUCCESS,
               "42#####",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42####",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123abc",
               j(fmt::format(R"({{"{}": 123}})", TARGET.substr(1))),
               3,
               getShortParser,
               {NAME, TARGET, {}, {}}),
        // Leading zeros
        ParseT(SUCCESS,
               "00042",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               5,
               getShortParser,
               {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(HalfFloatBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getHalfFloatParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getHalfFloatParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    HalfFloatParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS,
               "42",
               j(fmt::format(R"({{"{}": 42}})", TARGET.substr(1))),
               2,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42",
               j(fmt::format(R"({{"{}": -42}})", TARGET.substr(1))),
               3,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "3.14",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(3.14f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-3.14",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(-3.14f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "0",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               1,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "0.0",
               j(fmt::format(R"({{"{}": 0}})", TARGET.substr(1))),
               3,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-0.0",
               j(fmt::format(R"({{"{}": -0}})", TARGET.substr(1))),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "65504",
               j(fmt::format(R"({{"{}": 65504}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-65504",
               j(fmt::format(R"({{"{}": -65504}})", TARGET.substr(1))),
               6,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "65503.9",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(65503.9f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               7,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-65503.9",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(-65503.9f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               8,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "65505", {}, 5, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-65505", {}, 6, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "100000", {}, 6, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-100000", {}, 7, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "1000000", {}, 7, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1.5e3",
               j(fmt::format(R"({{"{}": 1500}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-1.5e3",
               j(fmt::format(R"({{"{}": -1500}})", TARGET.substr(1))),
               6,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1.5e-4",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(1.5e-4f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               6,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "6.5e4",
               j(fmt::format(R"({{"{}": 65000}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "6.5E4",
               j(fmt::format(R"({{"{}": 65000}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1e2",
               j(fmt::format(R"({{"{}": 100}})", TARGET.substr(1))),
               3,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1e+2",
               j(fmt::format(R"({{"{}": 100}})", TARGET.substr(1))),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1e-2",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(0.01f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "1e6", {}, 3, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-1e6", {}, 4, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "1e10", {}, 4, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "6.6e4", {}, 5, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "0.001",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(0.001f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "0.0001",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(0.0001f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               6,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "0.00001",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(0.00001f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               7,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-0.001",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(-0.001f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               6,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "1000",
               j(fmt::format(R"({{"{}": 1000}})", TARGET.substr(1))),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "10000",
               j(fmt::format(R"({{"{}": 10000}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "32767",
               j(fmt::format(R"({{"{}": 32767}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-32768",
               j(fmt::format(R"({{"{}": -32768}})", TARGET.substr(1))),
               6,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42.5    ",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(42.5f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "-42.5    ",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(-42.5f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "42.5#####",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(42.5f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               4,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123.456abc",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(123.456f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               7,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "00042.5",
               []()
               {
                   json::Json expected {};
                   expected.setFloat(42.5f, json::Json::formatJsonPath(TARGET.substr(1)));
                   return expected;
               }(),
               7,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "65504.0",
               j(fmt::format(R"({{"{}": 65504}})", TARGET.substr(1))),
               7,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "65500",
               j(fmt::format(R"({{"{}": 65500}})", TARGET.substr(1))),
               5,
               getHalfFloatParser,
               {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "65504.1", {}, 7, getHalfFloatParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "-65504.1", {}, 8, getHalfFloatParser, {NAME, TARGET, {}, {}})));




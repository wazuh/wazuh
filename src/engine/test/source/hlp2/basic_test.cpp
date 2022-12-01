#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>

#include "run_test.hpp"

TEST(HLP2, BaseEofError)
{
    std::string input = "0123456789";
    for (auto i = 0; i < input.size(); ++i)
    {
        auto result = hlp::internal::eofError<json::Json>(input, i);
        ASSERT_FALSE(result.has_value());
    }
    ASSERT_TRUE(hlp::internal::eofError<json::Json>(input, input.size()).has_value());
}

TEST(HLP2, BaseStopChar)
{
    std::string input = "0123456789";
    for (auto i = 0; i < input.size(); ++i)
    {
        auto result = hlp::internal::stop<json::Json>(input, 0, {std::string {input[i]}});
        ASSERT_TRUE(std::holds_alternative<std::string_view>(result));
        ASSERT_EQ(std::get<std::string_view>(result), input.substr(0, i));
        // Check that if stop is behind the index, it is not found
        for (auto j = 0; j < i; ++j)
        {
            auto resultFail =
                hlp::internal::stop<json::Json>(input, i, {std::string {input[j]}});
            ASSERT_TRUE(std::holds_alternative<parsec::Result<json::Json>>(resultFail));
            auto pResult = std::get<parsec::Result<json::Json>>(resultFail);
            ASSERT_TRUE(pResult.failure());
            ASSERT_EQ(pResult.index, 10);
            ASSERT_FALSE(pResult.error().msg.empty());
        }
    }
    // Check that stop is not found
    auto result = hlp::internal::stop<json::Json>(input, 0, {"10"});
    ASSERT_TRUE(std::holds_alternative<parsec::Result<json::Json>>(result));
    auto pResult = std::get<parsec::Result<json::Json>>(result);
    ASSERT_TRUE(pResult.failure());
    ASSERT_EQ(pResult.index, 10);
    ASSERT_FALSE(pResult.error().msg.empty());
}

TEST(HLP2, BaseStopStr)
{
    std::string input = "s0s1s2s3s4s5s6s7s8s9";
    for (auto i = 0; i < input.size(); i += 2)
    {
        auto result =
            hlp::internal::stop<json::Json>(input, 0, {"s" + std::to_string(int(i / 2))});
        ASSERT_TRUE(std::holds_alternative<std::string_view>(result));
        ASSERT_EQ(std::get<std::string_view>(result), input.substr(0, i));
        // Check that if stop is behind the index, it is not found
        for (auto j = 0; j < i; j += 2)
        {
            auto resultFail = hlp::internal::stop<json::Json>(
                input, i, {"s" + std::to_string(int(j / 2))});
            ASSERT_TRUE(std::holds_alternative<parsec::Result<json::Json>>(resultFail));
            auto pResult = std::get<parsec::Result<json::Json>>(resultFail);
            ASSERT_TRUE(pResult.failure());
            ASSERT_EQ(pResult.index, 20);
            ASSERT_FALSE(pResult.error().msg.empty());
        }
    }
    // Check that stop is not found
    auto result = hlp::internal::stop<json::Json>(input, 0, {"s10"});
    ASSERT_TRUE(std::holds_alternative<parsec::Result<json::Json>>(result));
    auto pResult = std::get<parsec::Result<json::Json>>(result);
    ASSERT_TRUE(pResult.failure());
    ASSERT_EQ(pResult.index, 20);
    ASSERT_FALSE(pResult.error().msg.empty());
}

TEST(HLP2, BooleanParser)
{
    ASSERT_THROW(hlp::getBoolParser({}, {"arg"}), std::runtime_error);

    auto fn = [](bool in) -> json::Json
    {
        json::Json doc;
        doc.setBool(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"true", true, {}, Options(), fn(true), 4},
        TestCase {"false", true, {}, Options(), fn(false), 5},
        TestCase {"true    ", true, {}, Options(), fn(true), 4},
        TestCase {"false    ", true, {}, Options(), fn(false), 5},
        TestCase {"    true", false, {}, Options(), {}, 0},
        TestCase {"    false", false, {}, Options(), {}, 0},
        TestCase {"true#####", true, {}, Options(), fn(true), 4},
        TestCase {"false####", true, {}, Options(), fn(false), 5},
        TestCase {"###true", false, {}, Options(), {}, 0},
        TestCase {"###false", false, {}, Options(), {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getBoolParser);
    }
}

TEST(HLP2, ByteParser)
{
    ASSERT_THROW(hlp::getByteParser({}, {"arg"}), std::runtime_error);

    auto fn = [](int8_t in) -> json::Json
    {
        json::Json doc;
        doc.setInt(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"42", true, {}, Options(), fn(42), 2},
        TestCase {"-42", true, {}, Options(), fn(-42), 3},
        TestCase {"128", false, {}, Options(), {}, 0},
        TestCase {"-129", false, {}, Options(), {}, 0},
        TestCase {"42    ", true, {}, Options(), fn(42), 2},
        TestCase {"-42    ", true, {}, Options(), fn(-42), 3},
        TestCase {"    42", false, {}, Options(), {}, 0},
        TestCase {"    -42", false, {}, Options(), {}, 0},
        TestCase {"42#####", true, {}, Options(), fn(42), 2},
        TestCase {"-42####", true, {}, Options(), fn(-42), 3},
        TestCase {"###42", false, {}, Options(), {}, 0},
        TestCase {"###-42", false, {}, Options(), {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getByteParser);
    }
}

TEST(HLP2, LongParser)
{
    ASSERT_THROW(hlp::getLongParser({}, {"arg"}), std::runtime_error);

    auto fn = [](int64_t in) -> json::Json
    {
        json::Json doc;
        doc.setInt64(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"42", true, {}, Options {}, fn(42), 2},
        TestCase {"-42", true, {}, Options {}, fn(-42), 3},
        TestCase {"9223372036854775808", false, {}, Options {}, {}, 0},
        // writing this test makes the compiler round the number to fit the type,
        // we cannot test the inferior limit of uint64_t easily
        // TestCase {"-9223372036854775808", true, {}, Options {},
        // fn(-9223372036854775808), 20},
        TestCase {"42    ", true, {}, Options {}, fn(42), 2},
        TestCase {"-42    ", true, {}, Options {}, fn(-42), 3},
        TestCase {"    42", false, {}, Options {}, {}, 0},
        TestCase {"    -42", false, {}, Options {}, {}, 0},
        TestCase {"42#####", true, {}, Options {}, fn(42), 2},
        TestCase {"-42####", true, {}, Options {}, fn(-42), 3},
        TestCase {"###42", false, {}, Options {}, {}, 0},
        TestCase {"###-42", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getLongParser);
    }
}

TEST(HLP2, FloatParser)
{
    ASSERT_THROW(hlp::getFloatParser({}, {"arg"}), std::runtime_error);

    auto fn = [](float_t in) -> json::Json
    {
        json::Json doc;
        doc.setFloat(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"42.0", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"3.40282e+38", true, {}, Options {}, fn(3.40282e+38), 11},
        TestCase {"-3.40282e+38", true, {}, Options {}, fn(-3.40282e+38), 12},
        TestCase {"42.0    ", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0   ", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"    42.0", false, {}, Options {}, {}, 0},
        TestCase {"    -42.0", false, {}, Options {}, {}, 0},
        TestCase {"42.0#####", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-420.0####", true, {}, Options {}, fn(-420.0), 6},
        TestCase {"###42.0", false, {}, Options {}, {}, 0},
        TestCase {"###-42.0", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getFloatParser);
    }
}

TEST(HLP2, DoubleParser)
{
    ASSERT_THROW(hlp::getDoubleParser({}, {"arg"}), std::runtime_error);

    auto fn = [](double_t in) -> json::Json
    {
        json::Json doc;
        doc.setDouble(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"42.0", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"1.79769e+308", true, {}, Options {}, fn(1.79769e+308), 12},
        TestCase {"-1.79769e+308", true, {}, Options {}, fn(-1.79769e+308), 13},
        TestCase {"42.0    ", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0   ", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"    42.0", false, {}, Options {}, {}, 0},
        TestCase {"    -42.0", false, {}, Options {}, {}, 0},
        TestCase {"42.0#####", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-420.0####", true, {}, Options {}, fn(-420.0), 6},
        TestCase {"###42.0", false, {}, Options {}, {}, 0},
        TestCase {"###-42.0", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getDoubleParser);
    }
}

TEST(HLP2, ScaledFloatParser)
{
    ASSERT_THROW(hlp::getScaledFloatParser({}, {"arg"}), std::runtime_error);

    auto fn = [](double_t in) -> json::Json
    {
        json::Json doc;
        doc.setDouble(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"42.0", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"1.79769e+308", true, {}, Options {}, fn(1.79769e+308), 12},
        TestCase {"-1.79769e+308", true, {}, Options {}, fn(-1.79769e+308), 13},
        TestCase {"42.0    ", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0   ", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"    42.0", false, {}, Options {}, {}, 0},
        TestCase {"    -42.0", false, {}, Options {}, {}, 0},
        TestCase {"42.0#####", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-420.0####", true, {}, Options {}, fn(-420.0), 6},
        TestCase {"###42.0", false, {}, Options {}, {}, 0},
        TestCase {"###-42.0", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getScaledFloatParser);
    }
}

TEST(HLP2, TextParser)
{
    ASSERT_THROW(hlp::getTextParser({}, {}), std::runtime_error);
    ASSERT_THROW(hlp::getTextParser({""}, {"arg"}), std::runtime_error);

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"A random text which stops before stop",
                  true,
                  {"stop"},
                  Options {},
                  fn("A random text which "),
                  20},
        TestCase {"This can't be parsed because it can't sto",
                  false,
                  {"#"},
                  Options {},
                  {},
                  41},
        TestCase {"stop return empty match", false, {"stop"}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getTextParser);
    }
}

TEST(HLP2, BinaryParser)
{
    ASSERT_THROW(hlp::getBinaryParser({}, {"arg"}), std::runtime_error);

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"aGVsbG8=", true, {}, Options {}, fn("aGVsbG8="), 8},
        TestCase {"aGVsbG9z", true, {}, Options {}, fn("aGVsbG9z"), 8},
        TestCase {"aGVsbG==", true, {}, Options {}, fn("aGVsbG=="), 8},
        TestCase {"aGVsbG9z ", true, {}, Options {}, fn("aGVsbG9z"), 8},
        TestCase {" aGVsbG9z", false, {}, Options {}, {}, 0},
        TestCase {"aGVsbG9", false, {}, Options {}, {}, 7},
        TestCase {"aGVsbG9 ", false, {}, Options {}, {}, 7},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getBinaryParser);
    }
}

TEST(HLP2, IPParser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        // <ip>:<puerto>
        // http://[2001:db8:4006:812::200e]:8080/path/page.html.
        TestCase {"192.168.0.1:8080", true, {":"}, Options {}, fn("192.168.0.1"), 11},
        TestCase {"192.168.1.1", true, {""}, Options {}, fn("192.168.1.1"), 11},
        TestCase {"::", true, {""}, Options {}, fn("::"), 2},
        TestCase {":: ", true, {" "}, Options {}, fn("::"), 2},
        TestCase {"192.168.1.1 ", true, {" "}, Options {}, fn("192.168.1.1"), 11},
        TestCase {"555.168.1.1 ", false, {" "}, Options {}, fn("192.168.1.1"), 0},
        TestCase {"192.168.1.1192", false, {"192"}, Options {}, fn("192.168.1.1"), 0},
        TestCase {"127.1", false, {}, Options {}, fn("127.1"), 0},
        TestCase {"1:2:3:4:5:6:77.77.88.88",
                  true,
                  {""},
                  Options {},
                  fn("1:2:3:4:5:6:77.77.88.88"),
                  23},
        TestCase {
            "0xc0.0xa8.0x8c.0xff", false, {""}, Options {}, fn("0xc0.0xa8.0x8c.0xff"), 0},
        TestCase {"001.002.003.004", false, {""}, Options {}, fn("001.002.003.004"), 0},
        TestCase {"1::1.2.3.4", true, {""}, Options {}, fn("1::1.2.3.4"), 10},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getIPParser);
    }
}

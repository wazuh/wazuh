#ifndef RUNTEST
#define RUNTEST
#include <gtest/gtest.h>

#include <functional>
#include <list>
#include <optional>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

#define GTEST_COUT std::cerr << "[          ] [ DEBUG ] "

using namespace hlp;

// A TestCase is a tuple of
//   [0] std::string input to parse,
//   [1] bool to know if the parsing was succesful
//   [2] std::optional<std::string> optional stop string,
//   [3] std::list<std::string> options,
//   [4] std::string which will be inside the json::Json returned value,
//   [5] int index position
//   [6] ReturnDoc a funcion wihch receives [4] and returns a json::Json document
using TestCase = std::tuple<std::string, bool, Stop, Options, json::Json, size_t>;

static void runTest(TestCase t,
                    std::function<parsec::Parser<json::Json>(Stop, Options)> pb)
{
    parsec::Parser<json::Json> parser;
    auto expectedSuccess = std::get<1>(t);
    auto expectedDoc = std::get<4>(t);
    try
    {
        parser = pb(std::get<2>(t), std::get<3>(t));
    }
    catch (std::invalid_argument& e)
    {
        ASSERT_FALSE(expectedSuccess)
            << fmt::format("Error building parser: {}", e.what());
        return;
    }
    auto r = parser(std::get<0>(t), 0);

    ASSERT_EQ(r.success(), expectedSuccess)
        << (r.success() ? "" : "ParserError: " + r.error().msg);
    if (r.success())
    {
        ASSERT_EQ(expectedDoc, r.value());
    }
    else
    {
        ASSERT_FALSE(r.error().msg.empty());
    }
    ASSERT_EQ(r.text, std::get<0>(t));
    ASSERT_EQ(r.index, std::get<5>(t));
}
#endif // WAZUH_ENGINE_HLP_H

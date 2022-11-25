#ifndef RUNTEST
#define RUNTEST

#include <json/json.hpp>
#include <optional>
#include <list>
#include <functional>
#include <hlp/parsec.hpp>
#include <gtest/gtest.h>
#include "fmt/format.h"

#define GTEST_COUT std::cerr << "[          ] [ DEBUG ] "

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

// A TestCase is a tuple of
//   [0] std::string input to parse,
//   [1] bool to know if the parsing was succesful
//   [2] std::optional<std::string> optional stop string,
//   [3] std::list<std::string> options,
//   [4] std::string which will be inside the json::Json returned value,
//   [5] int index position
//   [6] ReturnDoc a funcion wihch receives [4] and returns a json::Json document
using TestCase = std::tuple<std::string, bool, Stop, Options, json::Json, size_t>;

static void runTest(TestCase t, std::function<parsec::Parser<json::Json>(Stop, Options)> pb)
{
    parsec::Parser<json::Json> parser;
    auto expectedSuccess = std::get<1>(t);
    auto expectedDoc =  std::get<4>(t);
    try {
        parser = pb(std::get<2>(t), std::get<3>(t));
    } catch (std::invalid_argument & e) {
        GTEST_COUT << fmt::format("Error building parser: {}",e.what() ) << std::endl;
        SCOPED_TRACE(fmt::format("Error building parser: {}",e.what() ));
        ASSERT_FALSE(expectedSuccess);
        return;
    }
    auto r = parser(std::get<0>(t), 0);
    GTEST_COUT << fmt::format("Input: '{}'", std::get<0>(t)) << std::endl;
    SCOPED_TRACE(fmt::format("Input: '{}'", std::get<0>(t)));
    ASSERT_EQ(r.success(), expectedSuccess);
    if (r.success())
    {
        ASSERT_EQ(expectedDoc, r.value());
    }
    else
    {
        SCOPED_TRACE(fmt::format("Parser error: {}",r.error().msg ));
        ASSERT_FALSE(r.error().msg.empty());
        GTEST_COUT << fmt::format("Parser error: {}",r.error().msg ) << std::endl;
        return;
    }
    ASSERT_EQ(r.text, std::get<0>(t));
    ASSERT_EQ(r.index, std::get<5>(t));
}
#endif // WAZUH_ENGINE_HLP_H
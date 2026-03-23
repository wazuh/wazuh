#ifndef _HLP_TEST_HPP
#define _HLP_TEST_HPP

#include <gtest/gtest.h>

#include <iostream>

#include <fmt/format.h>

#include <hlp/hlp.hpp>

using BuildT = std::tuple<bool, hlp::ParserBuilder, hlp::Params>;
class HlpBuildTest : public ::testing::TestWithParam<BuildT>
{
};

using ParseT = std::tuple<bool, std::string, json::Json, size_t, hlp::ParserBuilder, hlp::Params>;
class HlpParseTest : public ::testing::TestWithParam<ParseT>
{
};

using namespace hlp::parsers;

inline json::Json j(const std::string& str)
{
    return json::Json(str.c_str());
}

auto constexpr SUCCESS = true;
auto constexpr FAILURE = false;

#endif // _HLP_TEST_HPP

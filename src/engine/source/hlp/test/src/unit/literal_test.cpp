#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "textParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(LiteralBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getLiteralParser, {NAME, TARGET, {}, {}}),
                                           BuildT(SUCCESS, getLiteralParser, {NAME, TARGET, {}, {"lit"}})));

INSTANTIATE_TEST_SUITE_P(LiteralParse,
                         HlpParseTest,
                         ::testing::Values(ParseT(SUCCESS,
                                                  "a",
                                                  j(fmt::format(R"({{"{}":"a"}})", TARGET.substr(1))),
                                                  1,
                                                  getLiteralParser,
                                                  {NAME, TARGET, {}, {"a"}}),
                                           ParseT(FAILURE, "a", {}, 0, getLiteralParser, {NAME, TARGET, {}, {"b"}}),
                                           ParseT(SUCCESS,
                                                  "ab",
                                                  j(fmt::format(R"({{"{}":"ab"}})", TARGET.substr(1))),
                                                  2,
                                                  getLiteralParser,
                                                  {NAME, TARGET, {}, {"ab"}}),
                                           ParseT(FAILURE, "ab", {}, 0, getLiteralParser, {NAME, TARGET, {}, {"abc"}}),
                                           ParseT(SUCCESS,
                                                  "abc",
                                                  j(fmt::format(R"({{"{}":"ab"}})", TARGET.substr(1))),
                                                  2,
                                                  getLiteralParser,
                                                  {NAME, TARGET, {}, {"ab"}})));

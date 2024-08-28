#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "textParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(TextBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getTextParser, {NAME, TARGET, {""}, {"unexpected"}}),
                                           BuildT(FAILURE, getTextParser, {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(
    TextParse,
    HlpParseTest,
    ::testing::Values(ParseT(SUCCESS,
                             "a",
                             j(fmt::format(R"({{"{}":"a"}})", TARGET.substr(1))),
                             1,
                             getTextParser,
                             {NAME, TARGET, {""}, {}}),
                      ParseT(FAILURE, "a", {}, 0, getTextParser, {NAME, TARGET, {"a"}, {}}),
                      ParseT(SUCCESS,
                             "ab",
                             j(fmt::format(R"({{"{}":"a"}})", TARGET.substr(1))),
                             1,
                             getTextParser,
                             {NAME, TARGET, {"b"}, {}}),
                      ParseT(SUCCESS,
                             "ac",
                             j(fmt::format(R"({{"{}":"a"}})", TARGET.substr(1))),
                             1,
                             getTextParser,
                             {NAME, TARGET, {"b", "c"}, {}}),
                      ParseT(FAILURE, "abc", {}, 0, getTextParser, {NAME, TARGET, {"d"}, {}}),
                      ParseT(FAILURE, "abc", {}, 0, getTextParser, {NAME, TARGET, {"d", "e"}, {}})));

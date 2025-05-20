#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "betweenParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(
    BetweenBuild,
    HlpBuildTest,
    ::testing::Values(BuildT(FAILURE, getBetweenParser, {NAME, TARGET, {}, {}}),
                      BuildT(FAILURE, getBetweenParser, {NAME, TARGET, {}, {"one"}}),
                      BuildT(SUCCESS, getBetweenParser, {NAME, TARGET, {}, {"one", "two"}}),
                      BuildT(FAILURE, getBetweenParser, {NAME, TARGET, {}, {"one", "two", "three"}}),
                      BuildT(SUCCESS, getBetweenParser, {NAME, TARGET, {}, {"", "two"}}),
                      BuildT(SUCCESS, getBetweenParser, {NAME, TARGET, {}, {"one", ""}}),
                      BuildT(FAILURE, getBetweenParser, {NAME, TARGET, {}, {"", ""}})));

INSTANTIATE_TEST_SUITE_P(
    BetweenParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS,
               "[start]value[end]",
               j(fmt::format(R"({{"{}": "value"}})", TARGET.substr(1))),
               17,
               getBetweenParser,
               {NAME, TARGET, {}, {"[start]", "[end]"}}),
        ParseT(SUCCESS,
               "[start][end]",
               j(fmt::format(R"({{"{}": ""}})", TARGET.substr(1))),
               12,
               getBetweenParser,
               {NAME, TARGET, {}, {"[start]", "[end]"}}),
        ParseT(SUCCESS,
               "[start]",
               j(fmt::format(R"({{"{}": ""}})", TARGET.substr(1))),
               7,
               getBetweenParser,
               {NAME, TARGET, {}, {"[start]", ""}}),
        ParseT(SUCCESS,
               "[end]",
               j(fmt::format(R"({{"{}": ""}})", TARGET.substr(1))),
               5,
               getBetweenParser,
               {NAME, TARGET, {}, {"", "[end]"}}),
        ParseT(SUCCESS,
               "[start]value[end] after end",
               j(fmt::format(R"({{"{}": "value"}})", TARGET.substr(1))),
               17,
               getBetweenParser,
               {NAME, TARGET, {}, {"[start]", "[end]"}}),
        ParseT(FAILURE, "[other]value[end]", {}, 0, getBetweenParser, {NAME, TARGET, {}, {"[start]", "[end]"}}),
        ParseT(FAILURE, "[start]value[other]", {}, 0, getBetweenParser, {NAME, TARGET, {}, {"[start]", "[end]"}}),
        ParseT(SUCCESS,
               "[start]value[end][end]",
               j(fmt::format(R"({{"{}": "value"}})", TARGET.substr(1))),
               17,
               getBetweenParser,
               {NAME, TARGET, {}, {"[start]", "[end]"}}),
        ParseT(SUCCESS,
               "[start][start]value[end]",
               j(fmt::format(R"({{"{}": "[start]value"}})", TARGET.substr(1))),
               24,
               getBetweenParser,
               {NAME, TARGET, {}, {"[start]", "[end]"}})));

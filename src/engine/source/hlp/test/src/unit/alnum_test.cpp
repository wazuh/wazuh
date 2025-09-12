#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "alphanumParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(
    AlnumBuild,
    HlpBuildTest,
    ::testing::Values(BuildT(SUCCESS, getAlphanumericParser, {NAME, TARGET, {}, {}}),
                      BuildT(SUCCESS, getAlphanumericParser, {NAME, TARGET, {}, {"-.,_(){}"}}),
                      BuildT(SUCCESS, getAlphanumericParser, {NAME, TARGET, {}, {"abcDEF123"}}),
                      BuildT(FAILURE, getAlphanumericParser, {NAME, TARGET, {}, {"-", "unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    AlnumParse,
    HlpParseTest,
    ::testing::Values(ParseT(SUCCESS,
                             "abc1234ABC",
                             j(fmt::format(R"({{"{}":"abc1234ABC"}})", TARGET.substr(1))),
                             10,
                             getAlphanumericParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             "abc1234ABC_",
                             j(fmt::format(R"({{"{}":"abc1234ABC"}})", TARGET.substr(1))),
                             10,
                             getAlphanumericParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             ":abc-1234_ABC.",
                             j(fmt::format(R"({{"{}":":abc-1234_ABC."}})", TARGET.substr(1))),
                             14,
                             getAlphanumericParser,
                             {NAME, TARGET, {}, {":-_."}}),
                      ParseT(FAILURE, "_a", {}, 0, getAlphanumericParser, {NAME, TARGET, {}, {}}),
                      ParseT(FAILURE, "_a", {}, 0, getAlphanumericParser, {NAME, TARGET, {}, {"-"}})));

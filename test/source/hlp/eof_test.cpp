#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "eofParser";
static const std::string TARGET = "/Unused";

INSTANTIATE_TEST_SUITE_P(EofBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getEofParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getEofParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(EofParse,
                         HlpParseTest,
                         ::testing::Values(ParseT(SUCCESS, "", j("{}"), 0, getEofParser, {NAME, TARGET, {}, {}}),
                                           ParseT(FAILURE, "a", {}, 0, getEofParser, {NAME, TARGET, {}, {}})));

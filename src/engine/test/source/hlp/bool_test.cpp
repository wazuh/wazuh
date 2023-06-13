#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "boolParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(BoolBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getBoolParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getBoolParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    BoolParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS, "true", j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))), 4, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "false", j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))), 5, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "tru", {}, 0, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "fals", {}, 0, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS, "trueaaa", j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))), 4, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS, "falseaaa", j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))), 5, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "TRUE", j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))), 4, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "FALSE", j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))), 5, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "True", j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))), 4, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "False", j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))), 5, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "atrue", {}, 0, getBoolParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, "afalse", {}, 0, getBoolParser, {NAME, TARGET, {}, {}})));

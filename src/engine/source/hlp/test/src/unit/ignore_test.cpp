#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "ignoreParser";

INSTANTIATE_TEST_SUITE_P(IgnoreBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getIgnoreParser, {NAME, "", {}, {}}),
                                           BuildT(SUCCESS, getIgnoreParser, {NAME, "", {}, {"ignore"}}),
                                           BuildT(FAILURE, getIgnoreParser, {NAME, "", {}, {"ignore", "unexpected"}}),
                                           BuildT(FAILURE, getIgnoreParser, {NAME, "not allow", {}, {"ignore"}})));

INSTANTIATE_TEST_SUITE_P(
    IgnoreParse,
    HlpParseTest,
    ::testing::Values(ParseT(SUCCESS, "wazuh", j("{}"), 5, getIgnoreParser, {NAME, "", {}, {"wazuh"}}),
                      ParseT(SUCCESS, "wazuh 123", j("{}"), 5, getIgnoreParser, {NAME, "", {}, {"wazuh"}}),
                      ParseT(SUCCESS, "wazuhwazuh", j("{}"), 10, getIgnoreParser, {NAME, "", {}, {"wazuh"}}),
                      ParseT(SUCCESS, "wazuhwazuhwazuhwazuh", j("{}"), 20, getIgnoreParser, {NAME, "", {}, {"wazuh"}}),
                      ParseT(SUCCESS, "wazuhwa", j("{}"), 5, getIgnoreParser, {NAME, "", {}, {"wazuh"}}),
                      ParseT(FAILURE, "WAZUH", j("{}"), 0, getIgnoreParser, {NAME, "", {}, {"wazuh"}})));

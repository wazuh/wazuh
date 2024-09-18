#include "gtest/gtest.h"
#include <base/utils/timeUtils.hpp>
#include <regex>

class timeUtilsTest : public ::testing::Test
{
protected:
    timeUtilsTest() = default;
    virtual ~timeUtilsTest() = default;
};

TEST(timeUtilsTest, CheckCurrentDateDefaultSeparator)
{
    constexpr auto DATE_FORMAT_REGEX_STR {"[0-9]{4}/([0-9]|1[0-2]){2}/(([0-9]|1[0-2]){2})"};
    const auto currentData {base::utils::time::getCurrentDate()};
    EXPECT_TRUE(std::regex_match(currentData, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST(timeUtilsTest, CheckCurrentDateCustomSeparator)
{
    constexpr auto DATE_FORMAT_REGEX_STR {"[0-9]{4}.([0-9]|1[0-2]){2}.(([0-9]|1[0-2]){2})"};
    const auto currentData {base::utils::time::getCurrentDate(".")};
    EXPECT_TRUE(std::regex_match(currentData, std::regex(DATE_FORMAT_REGEX_STR)));
}

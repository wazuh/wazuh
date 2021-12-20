/**
 * @brief Environment Test Suite
 */
#include <string>
#include <gtest/gtest.h>
#include <sandbox/environment.hpp>

TEST(EnvironmentTest, CreateEnvironment)
{
    auto e = Sandbox::Environment(std::string("MyTestEnvironment"));
}

TEST(EnvironmentTest, ToggleIsEnabledEnvironment)
{
    auto e = Sandbox::Environment(std::string("MyTestEnvironment"));
    ASSERT_EQ(e.isEnabled(), false);
    ASSERT_EQ(e.toggle(), true);
    ASSERT_EQ(e.isEnabled(), true);
    ASSERT_EQ(e.toggle(), false);
    ASSERT_EQ(e.isEnabled(), false);
}


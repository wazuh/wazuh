#ifndef _CONFIG_TEST_UTILS_HPP
#define _CONFIG_TEST_UTILS_HPP

#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

#include <gtest/gtest.h>

#include <conf/unitconf.hpp>

/************************************************************************
 *                              test getEnv
 ************************************************************************/
inline void setEnv(const std::string& env, const std::string& value)
{
    setenv(env.c_str(), value.c_str(), 1);

    // Check if the environment variable was set correctly
    const auto pValue = std::getenv(env.c_str());
    if (pValue == nullptr)
    {
        FAIL() << "Failed to set environment variable: " << env;
    }
    const auto envValue = std::string(pValue);
    EXPECT_EQ(envValue, value);
}

inline void unsetEnv(const std::string& env)
{
    unsetenv(env.c_str());

    // Check if the environment variable was unset correctly
    const auto pValue = std::getenv(env.c_str());
    if (pValue != nullptr)
    {
        FAIL() << "Failed to unset environment variable: " << env;
    }
}

#endif // _CONFIG_TEST_UTILS_HPP

// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CONFIG_TEST_UTILS_HPP
#define _CONFIG_TEST_UTILS_HPP

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
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

// Restore the caller's environment even when a test assertion exits early.
class ScopedEnv
{
public:
    explicit ScopedEnv(std::string name)
        : m_name(std::move(name))
    {
        if (const auto value = std::getenv(m_name.c_str()))
        {
            m_original = value;
        }
        unsetenv(m_name.c_str());
    }
    ~ScopedEnv()
    {
        if (m_original)
        {
            setenv(m_name.c_str(), m_original->c_str(), 1);
        }
        else
        {
            unsetenv(m_name.c_str());
        }
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    std::string m_name;
    std::optional<std::string> m_original;
};

#endif // _CONFIG_TEST_UTILS_HPP

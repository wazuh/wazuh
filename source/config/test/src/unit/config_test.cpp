#include <gtest/gtest.h>

#include <config/config.hpp>

TEST(ConfigTest, ConfigTest)
{
    auto config =  config::Config();

    EXPECT_NO_THROW(config.load());

    // Test the configuration
    auto val = config.get<int>("/server/thread_pool_size");
}

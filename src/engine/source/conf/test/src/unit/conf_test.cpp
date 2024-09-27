#include <gtest/gtest.h>

#include <conf/conf.hpp>

TEST(ConfigTest, ConfigTest)
{
    auto config =  conf::Conf();

    EXPECT_NO_THROW(config.load());

    // Test the configuration
    auto val = config.get<int>("/server/thread_pool_size");
}

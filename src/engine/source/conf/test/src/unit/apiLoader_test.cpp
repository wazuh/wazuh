#include <memory>

#include <gtest/gtest.h>

#include <conf/apiLoader.hpp>

TEST(ApiLoader, Load)
{
    std::shared_ptr<conf::IApiLoader> apiLoader = std::make_shared<conf::ApiLoader>();
    EXPECT_NO_THROW((*apiLoader)());
}

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include <ctistore/cm.hpp>

TEST(ContentManagerTest, init)
{
    // Dummy test to verify that ContentManager can be instantiated.
    std::unique_ptr<cti::store::ContentManager> cm = std::make_unique<cti::store::ContentManager>();
    ASSERT_NE(cm, nullptr);
}

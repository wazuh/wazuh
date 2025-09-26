#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include <cmsync/cmsync.hpp>

TEST(ContentManagerTest, init)
{
    // Dummy test to verify that ContentManager can be instantiated.
    auto cm = std::make_shared<cm::sync::CMSync>();
    ASSERT_NE(cm, nullptr);
}

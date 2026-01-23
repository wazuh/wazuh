#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include <cmsync/cmsync.hpp>

#include "storens.hpp"

TEST(ContentManagerTest, init)
{
    cm::sync::CmsyncNS store (cm::sync::NamespaceId("test"), std::filesystem::temp_directory_path(), std::filesystem::temp_directory_path());
    GTEST_SKIP() << "Not implemented yet.";
}

#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include <cmstore/cmstore.hpp>

#include "storens.hpp"

TEST(ContentManagerTest, init)
{
    cm::store::CMStoreNS store (cm::store::NamespaceId("test"), std::filesystem::temp_directory_path());
    GTEST_SKIP() << "Not implemented yet.";
}

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>

#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>

#include <memory>

TEST(ScaPolicyLoaderTest, Contruction)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    const SCAPolicyLoader loader({}, {}, fsMock);
    SUCCEED();
}

TEST(ScaPolicyLoaderTest, NoPolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    const SCAPolicyLoader loader({}, {}, fsMock, dbSync);
    ASSERT_EQ(loader.LoadPolicies([](auto, auto) { return; }).size(), 0);
}

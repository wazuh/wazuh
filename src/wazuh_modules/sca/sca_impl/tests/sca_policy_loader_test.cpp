#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>

#include "logging_helper.hpp"

#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>

#include <memory>

class ScaPolicyLoaderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Set up the logging callback to avoid "Log callback not set" errors
        LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {
            // Mock logging callback that does nothing
        });

    }
};

TEST_F(ScaPolicyLoaderTest, Contruction)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    const SCAPolicyLoader loader({}, fsMock);
    SUCCEED();
}

TEST_F(ScaPolicyLoaderTest, NoPolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    const SCAPolicyLoader loader({}, fsMock, dbSync);
    ASSERT_EQ(loader.LoadPolicies(30, true, [](auto, auto) { return; }).size(), 0);
}

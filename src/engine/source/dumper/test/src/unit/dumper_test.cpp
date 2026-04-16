#include <atomic>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <dumper/dumper.hpp>
#include <streamlog/mockStreamlog.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

namespace
{
const streamlog::RotationConfig TEST_CHANNEL_CONFIG {.basePath = "/tmp/test-logs",
                                                     .pattern = "${YYYY}/${MMM}/wazuh-${name}-${DD}.json",
                                                     .maxSize = 0,
                                                     .bufferSize = 1 << 20,
                                                     .shouldCompress = false,
                                                     .compressionLevel = 5};
} // namespace

class DumperTest : public ::testing::Test
{
protected:
    std::shared_ptr<streamlog::mocks::MockILogManager> m_mockLogManager;
    std::shared_ptr<streamlog::mocks::MockWriterEvent> m_mockWriterEvent;

    void SetUp() override
    {
        m_mockLogManager = std::make_shared<streamlog::mocks::MockILogManager>();
        m_mockWriterEvent = std::make_shared<streamlog::mocks::MockWriterEvent>();
    }

    void TearDown() override
    {
        m_mockLogManager.reset();
        m_mockWriterEvent.reset();
    }
};

TEST_F(DumperTest, ConstructorWithInvalidLogger)
{
    // Test constructor with null logger
    std::weak_ptr<streamlog::ILogManager> nullLogger;

    EXPECT_THROW(dumper::Dumper dumper(nullLogger, TEST_CHANNEL_CONFIG), std::runtime_error);
}

TEST_F(DumperTest, ConstructorInactive)
{
    // Test constructor with inactive state (default)
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;

    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);
    EXPECT_FALSE(dumper.isActive());
}

TEST_F(DumperTest, ConstructorActive)
{
    // Test constructor with active state
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);
    EXPECT_TRUE(dumper.isActive());
}

TEST_F(DumperTest, IsActiveWhenInactive)
{
    // Test isActive when dumper is inactive
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);

    EXPECT_FALSE(dumper.isActive());
}

TEST_F(DumperTest, IsActiveWhenActive)
{
    // Test isActive when dumper is active
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);
    EXPECT_TRUE(dumper.isActive());
}

TEST_F(DumperTest, Activate)
{
    // Test activation
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);

    EXPECT_FALSE(dumper.isActive());

    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    dumper.activate();
    EXPECT_TRUE(dumper.isActive());
}

TEST_F(DumperTest, ActivateWhenAlreadyActive)
{
    // Test activation when already active (should not call ensureAndGetWriter again)
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);
    EXPECT_TRUE(dumper.isActive());

    // No additional calls expected
    dumper.activate();
    EXPECT_TRUE(dumper.isActive());
}

TEST_F(DumperTest, ActivateWithInvalidLogger)
{
    // Test activation when logger becomes invalid
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);

    // Reset the shared_ptr to make weak_ptr invalid
    m_mockLogManager.reset();

    EXPECT_THROW(dumper.activate(), std::runtime_error);
}

TEST_F(DumperTest, Deactivate)
{
    // Test deactivation
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);
    EXPECT_TRUE(dumper.isActive());

    dumper.deactivate();
    EXPECT_FALSE(dumper.isActive());
}

TEST_F(DumperTest, DeactivateWhenAlreadyInactive)
{
    // Test deactivation when already inactive
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);

    EXPECT_FALSE(dumper.isActive());
    dumper.deactivate();
    EXPECT_FALSE(dumper.isActive());
}

TEST_F(DumperTest, DumpStringWhenActive)
{
    // Test dumping string data when active
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);

    std::string testData = "Test data for dumping";
    EXPECT_CALL(*m_mockWriterEvent, CallOperator(testData)).WillOnce(Return(true));

    EXPECT_NO_THROW(dumper.dump(testData));
}

TEST_F(DumperTest, DumpStringWhenInactive)
{
    // Test dumping string data when inactive (should not call writer)
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);

    std::string testData = "Test data for dumping";

    // No calls expected to the writer
    EXPECT_NO_THROW(dumper.dump(testData));
}

TEST_F(DumperTest, DumpCStringWhenActive)
{
    // Test dumping C-string data when active
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);

    const char* testData = "Test C-string data";
    EXPECT_CALL(*m_mockWriterEvent, CallOperator(std::string(testData))).WillOnce(Return(true));

    EXPECT_NO_THROW(dumper.dump(testData));
}

TEST_F(DumperTest, DumpCStringWhenInactive)
{
    // Test dumping C-string data when inactive
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, false);

    const char* testData = "Test C-string data";

    // No calls expected to the writer
    EXPECT_NO_THROW(dumper.dump(testData));
}

TEST_F(DumperTest, DumpNullCString)
{
    // Test dumping null C-string (should return early)
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);

    // No calls expected to the writer for null data
    EXPECT_NO_THROW(dumper.dump(nullptr));
}

TEST_F(DumperTest, DumpEmptyCString)
{
    // Test dumping empty C-string (should return early)
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);

    const char* emptyData = "";

    // No calls expected to the writer for empty data
    EXPECT_NO_THROW(dumper.dump(emptyData));
}

TEST_F(DumperTest, DumpWriterReturnsFalse)
{
    // Test dumping when writer returns false
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);

    std::string testData = "Test data";
    EXPECT_CALL(*m_mockWriterEvent, CallOperator(testData)).WillOnce(Return(false));

    // Should not throw even if writer returns false
    EXPECT_NO_THROW(dumper.dump(testData));
}

TEST_F(DumperTest, ThreadSafety)
{
    // Test thread safety of isActive method
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);

    // Multiple threads calling isActive should be safe
    std::vector<std::thread> threads;
    std::atomic<int> activeCount {0};

    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back(
            [&dumper, &activeCount]()
            {
                for (int j = 0; j < 100; ++j)
                {
                    if (dumper.isActive())
                    {
                        activeCount++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(activeCount.load(), 1000); // All calls should see active state
}

TEST_F(DumperTest, DestructorCleansUp)
{
    // Test that destructor properly cleans up
    EXPECT_CALL(*m_mockLogManager, ensureAndGetWriter(dumper::CHANNEL_NAME, _, _)).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;

    {
        dumper::Dumper dumper(weakLogger, TEST_CHANNEL_CONFIG, true);
        EXPECT_TRUE(dumper.isActive());
    } // Destructor called here

    // If we reach here without crash, destructor worked correctly
    SUCCEED();
}

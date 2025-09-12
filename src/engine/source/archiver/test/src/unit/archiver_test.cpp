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

#include <archiver/archiver.hpp>
#include <streamlog/mockStreamlog.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

class ArchiverTest : public ::testing::Test
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

TEST_F(ArchiverTest, ConstructorWithInvalidLogger)
{
    // Test constructor with null logger
    std::weak_ptr<streamlog::ILogManager> nullLogger;

    EXPECT_THROW(archiver::Archiver archiver(nullLogger), std::runtime_error);
}

TEST_F(ArchiverTest, ConstructorInactive)
{
    // Test constructor with inactive state (default)
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;

    archiver::Archiver archiver(weakLogger, false);
    EXPECT_FALSE(archiver.isActive());
}

TEST_F(ArchiverTest, ConstructorActive)
{
    // Test constructor with active state
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);
    EXPECT_TRUE(archiver.isActive());
}

TEST_F(ArchiverTest, IsActiveWhenInactive)
{
    // Test isActive when archiver is inactive
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, false);

    EXPECT_FALSE(archiver.isActive());
}

TEST_F(ArchiverTest, IsActiveWhenActive)
{
    // Test isActive when archiver is active
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);
    EXPECT_TRUE(archiver.isActive());
}

TEST_F(ArchiverTest, Activate)
{
    // Test activation
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, false);

    EXPECT_FALSE(archiver.isActive());

    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    archiver.activate();
    EXPECT_TRUE(archiver.isActive());
}

TEST_F(ArchiverTest, ActivateWhenAlreadyActive)
{
    // Test activation when already active (should not call getWriter again)
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);
    EXPECT_TRUE(archiver.isActive());

    // No additional calls expected
    archiver.activate();
    EXPECT_TRUE(archiver.isActive());
}

TEST_F(ArchiverTest, ActivateWithInvalidLogger)
{
    // Test activation when logger becomes invalid
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, false);

    // Reset the shared_ptr to make weak_ptr invalid
    m_mockLogManager.reset();

    EXPECT_THROW(archiver.activate(), std::runtime_error);
}

TEST_F(ArchiverTest, Deactivate)
{
    // Test deactivation
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);
    EXPECT_TRUE(archiver.isActive());

    archiver.deactivate();
    EXPECT_FALSE(archiver.isActive());
}

TEST_F(ArchiverTest, DeactivateWhenAlreadyInactive)
{
    // Test deactivation when already inactive
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, false);

    EXPECT_FALSE(archiver.isActive());
    archiver.deactivate();
    EXPECT_FALSE(archiver.isActive());
}

TEST_F(ArchiverTest, ArchiveStringWhenActive)
{
    // Test archiving string data when active
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);

    std::string testData = "Test data for archiving";
    EXPECT_CALL(*m_mockWriterEvent, CallOperator(testData)).WillOnce(Return(true));

    EXPECT_NO_THROW(archiver.archive(testData));
}

TEST_F(ArchiverTest, ArchiveStringWhenInactive)
{
    // Test archiving string data when inactive (should not call writer)
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, false);

    std::string testData = "Test data for archiving";

    // No calls expected to the writer
    EXPECT_NO_THROW(archiver.archive(testData));
}

TEST_F(ArchiverTest, ArchiveCStringWhenActive)
{
    // Test archiving C-string data when active
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);

    const char* testData = "Test C-string data";
    EXPECT_CALL(*m_mockWriterEvent, CallOperator(std::string(testData))).WillOnce(Return(true));

    EXPECT_NO_THROW(archiver.archive(testData));
}

TEST_F(ArchiverTest, ArchiveCStringWhenInactive)
{
    // Test archiving C-string data when inactive
    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, false);

    const char* testData = "Test C-string data";

    // No calls expected to the writer
    EXPECT_NO_THROW(archiver.archive(testData));
}

TEST_F(ArchiverTest, ArchiveNullCString)
{
    // Test archiving null C-string (should return early)
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);

    // No calls expected to the writer for null data
    EXPECT_NO_THROW(archiver.archive(nullptr));
}

TEST_F(ArchiverTest, ArchiveEmptyCString)
{
    // Test archiving empty C-string (should return early)
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);

    const char* emptyData = "";

    // No calls expected to the writer for empty data
    EXPECT_NO_THROW(archiver.archive(emptyData));
}

TEST_F(ArchiverTest, ArchiveWriterReturnsFalse)
{
    // Test archiving when writer returns false
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);

    std::string testData = "Test data";
    EXPECT_CALL(*m_mockWriterEvent, CallOperator(testData)).WillOnce(Return(false));

    // Should not throw even if writer returns false
    EXPECT_NO_THROW(archiver.archive(testData));
}

TEST_F(ArchiverTest, ThreadSafety)
{
    // Test thread safety of isActive method
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;
    archiver::Archiver archiver(weakLogger, true);

    // Multiple threads calling isActive should be safe
    std::vector<std::thread> threads;
    std::atomic<int> activeCount {0};

    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back(
            [&archiver, &activeCount]()
            {
                for (int j = 0; j < 100; ++j)
                {
                    if (archiver.isActive())
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

TEST_F(ArchiverTest, DestructorCleansUp)
{
    // Test that destructor properly cleans up
    EXPECT_CALL(*m_mockLogManager, getWriter("archives")).WillOnce(Return(m_mockWriterEvent));

    std::weak_ptr<streamlog::ILogManager> weakLogger = m_mockLogManager;

    {
        archiver::Archiver archiver(weakLogger, true);
        EXPECT_TRUE(archiver.isActive());
    } // Destructor called here

    // If we reach here without crash, destructor worked correctly
    SUCCEED();
}

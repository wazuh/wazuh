#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <random>
#include <thread>
#include <unistd.h>

#include <base/json.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <kvdb/kvdbManager.hpp>
#include <base/logging.hpp>
#include "fakeMetric.hpp"

namespace
{

const std::string KVDB_PATH {"/tmp/kvdb_test/"};
const std::string KVDB_DB_FILENAME {"TEST_DB"};

auto metricsManager = std::make_shared<FakeMetricManager>();

std::filesystem::path uniquePath(const std::string& path)
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid << "/"; // Unique path per thread and process
    return std::filesystem::path(path) / ss.str();
}

void Setup(const std::string& kvdbPath)
{
    logging::testInit();

    if (std::filesystem::exists(kvdbPath))
    {
        std::filesystem::remove_all(kvdbPath);
    }
}

void TearDown(const std::string& kvdbPath)
{
    if (std::filesystem::exists(kvdbPath))
    {
        std::filesystem::remove_all(kvdbPath);
    }
}

class KVDBManagerTest : public ::testing::Test
{
protected:
    std::shared_ptr<kvdbManager::IKVDBManager>  m_kvdbManager;
    std::string kvdbPath;

    void SetUp() override
    {
        kvdbPath = uniquePath(KVDB_PATH);
        ::Setup(kvdbPath);

        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};

        m_kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, metricsManager);

        m_kvdbManager->initialize();
    };

    void TearDown() override
    {
        try
        {
            m_kvdbManager->finalize();
        }
        catch (const std::exception& e)
        {
            FAIL() << "Exception: " << e.what();
        }

        ::TearDown(kvdbPath);
    };
};

TEST_F(KVDBManagerTest, Startup)
{
    ASSERT_NE(m_kvdbManager, nullptr);
}

TEST_F(KVDBManagerTest, InitializeDBInUseWithSameManager)
{
    // First initialize in setup
    ASSERT_NO_THROW(m_kvdbManager->initialize());
}

TEST_F(KVDBManagerTest, InitializeDBInUseWithOtherManager)
{
    // Open a locked DB
    kvdbManager::KVDBManagerOptions kvdbManagerOptions {KVDBManagerTest::kvdbPath, KVDB_DB_FILENAME};

    auto kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, metricsManager);

    ASSERT_THROW(kvdbManager->initialize(), std::runtime_error);
}

TEST_F(KVDBManagerTest, DeleteDB)
{
    // Create a DB
    ASSERT_EQ(m_kvdbManager->createDB("DeleteDB"), std::nullopt);

    // Delete the DB
    ASSERT_EQ(m_kvdbManager->deleteDB("DeleteDB"), std::nullopt);

    // Try to get the DB
    auto result = m_kvdbManager->getKVDBHandler("DeleteDB", "ut");
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
    ASSERT_EQ(std::get<base::Error>(result).message, "The DB 'DeleteDB' does not exists.");
}

TEST_F(KVDBManagerTest, DoubleDeleteDB)
{
    // Create a DB
    ASSERT_EQ(m_kvdbManager->createDB("DoubleDeleteDB"), std::nullopt);

    // Delete the DB
    ASSERT_EQ(m_kvdbManager->deleteDB("DoubleDeleteDB"), std::nullopt);

    // Double delete the DB
    auto result = m_kvdbManager->deleteDB("DoubleDeleteDB");
    ASSERT_NE(result, std::nullopt);
    ASSERT_EQ(result->message, "The DB 'DoubleDeleteDB' does not exists.");
}

TEST_F(KVDBManagerTest, DeleteAndCreateSameDB)
{
    // Create a DB
    ASSERT_EQ(m_kvdbManager->createDB("DeleteAndCreateSameDB"), std::nullopt);

    // Delete the DB
    ASSERT_EQ(m_kvdbManager->deleteDB("DeleteAndCreateSameDB"), std::nullopt);

    // Create a same DB
    ASSERT_EQ(m_kvdbManager->createDB("DeleteAndCreateSameDB"), std::nullopt);
}

TEST_F(KVDBManagerTest, DeleteDataBaseNoRestart)
{
    m_kvdbManager->createDB("DeleteDataBaseNoRestart");
    auto dbList = m_kvdbManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 1);
    ASSERT_EQ(dbList[0], "DeleteDataBaseNoRestart");
    auto createResult = m_kvdbManager->createDB("DeleteDataBaseNoRestart");
    ASSERT_FALSE(createResult.has_value());
    m_kvdbManager->deleteDB("DeleteDataBaseNoRestart");
    dbList = m_kvdbManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 0);
}

TEST_F(KVDBManagerTest, DeleteDataBaseWithRestart)
{
    m_kvdbManager->createDB("DeleteDataBaseWithRestart");
    auto dbList = m_kvdbManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 1);
    ASSERT_EQ(dbList[0], "DeleteDataBaseWithRestart");
    auto createResult = m_kvdbManager->createDB("DeleteDataBaseWithRestart");
    ASSERT_FALSE(createResult.has_value());
    m_kvdbManager->deleteDB("DeleteDataBaseWithRestart");
    dbList = m_kvdbManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 0);

    try
    {
        m_kvdbManager->finalize();
    }
    catch (const std::exception& e)
    {
        FAIL() << "Exception: " << e.what();
    }

    m_kvdbManager.reset();
    ASSERT_EQ(m_kvdbManager.use_count(), 0);

    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};
    m_kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, metricsManager);

    m_kvdbManager->initialize();

    dbList = m_kvdbManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 0);
}
} // namespace

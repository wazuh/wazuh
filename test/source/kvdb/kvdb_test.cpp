#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <random>

#include <kvdb/kvdbManager.hpp>
#include <testsCommon.hpp>

#include <metrics/metricsManager.hpp>

using namespace metricsManager;

namespace
{

const std::string KVDB_PATH {"/tmp/kvdbTestSuitePath/"};
const std::string KVDB_DB_FILENAME {"TEST_DB"};

std::shared_ptr<kvdbManager::KVDBManager> m_spKVDBManager;
std::string kvdbPath;

void Setup()
{
    initLogging();

    // cleaning directory in order to start without garbage.
    kvdbPath = generateRandomStringWithPrefix(6, KVDB_PATH) + "/";

    if (std::filesystem::exists(kvdbPath))
    {
        std::filesystem::remove_all(kvdbPath);
    }

    std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();

    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};

    m_spKVDBManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    m_spKVDBManager->initialize();
}

void TearDown()
{
    try
    {
        m_spKVDBManager->finalize();
    }
    catch (const std::exception& e)
    {
        FAIL() << "Exception: " << e.what();
    }

    if (std::filesystem::exists(kvdbPath))
    {
        std::filesystem::remove_all(kvdbPath);
    }
}

class DumpWithMultiplePages
    : public ::testing::TestWithParam<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t>>
{
protected:
    void SetUp() override { ::Setup(); }

    void TearDown() override { ::TearDown(); };
};

class KVDBTest : public ::testing::Test
{

protected:
    void SetUp() override { ::Setup(); };

    void TearDown() override { ::TearDown(); };

    void dumpScopeInfo(std::map<std::string, kvdbManager::RefInfo>& scopeInfo)
    {
        std::cout << "Dump Scopes Information: " << std::endl;

        for (auto& scope : scopeInfo)
        {
            std::cout << fmt::format("Scope: {}", scope.first) << std::endl;
            for (auto& handler : scope.second)
            {
                std::cout << fmt::format("    Handler: {}", handler.first) << std::endl;
            }
        }
    }
};

TEST_F(KVDBTest, Startup)
{
    ASSERT_NE(m_spKVDBManager, nullptr);
}

TEST_F(KVDBTest, InitializeDBInUseWithSameManager)
{
    // First initialize in setup
    ASSERT_NO_THROW(m_spKVDBManager->initialize());
}

TEST_F(KVDBTest, InitializeDBInUseWithOtherManager)
{
    std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();
    ASSERT_NE(spMetrics, nullptr);

    // Open a locked DB
    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};

    auto kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    ASSERT_THROW(kvdbManager->initialize(), std::runtime_error);
}

TEST_F(KVDBTest, DeleteDB)
{
    std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();
    ASSERT_NE(spMetrics, nullptr);

    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, "TEST_DB2"};

    auto kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    ASSERT_NO_THROW(kvdbManager->initialize());

    // Create a DB
    ASSERT_EQ(kvdbManager->createDB("test"), std::nullopt);

    // Delete the DB
    ASSERT_EQ(kvdbManager->deleteDB("test"), std::nullopt);

    // Try to get the DB
    auto result = kvdbManager->getKVDBHandler("test", "ut");
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
    ASSERT_EQ(std::get<base::Error>(result).message, "The DB 'test' does not exists.");
}

TEST_F(KVDBTest, DoubleDeleteDB)
{
    std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();
    ASSERT_NE(spMetrics, nullptr);

    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, "TEST_DB2"};

    auto kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    ASSERT_NO_THROW(kvdbManager->initialize());

    // Create a DB
    ASSERT_EQ(kvdbManager->createDB("test"), std::nullopt);

    // Delete the DB
    ASSERT_EQ(kvdbManager->deleteDB("test"), std::nullopt);

    // Double delete the DB
    auto result = kvdbManager->deleteDB("test");
    ASSERT_NE(result, std::nullopt);
    ASSERT_EQ(result->message, "The DB 'test' does not exists.");
}

TEST_F(KVDBTest, DeleteAndCreateSameDB)
{
    std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();
    ASSERT_NE(spMetrics, nullptr);

    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, "TEST_DB3"};

    auto kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    ASSERT_NO_THROW(kvdbManager->initialize());

    // Create a DB
    ASSERT_EQ(kvdbManager->createDB("test"), std::nullopt);

    // Delete the DB
    ASSERT_EQ(kvdbManager->deleteDB("test"), std::nullopt);

    // Create a same DB
    ASSERT_EQ(kvdbManager->createDB("test"), std::nullopt);
}

TEST_F(KVDBTest, DeleteDataBaseNoRestart)
{
    m_spKVDBManager->createDB("db_test");
    auto dbList = m_spKVDBManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 1);
    ASSERT_EQ(dbList[0], "db_test");
    auto createResult = m_spKVDBManager->createDB("db_test");
    ASSERT_FALSE(createResult.has_value());
    m_spKVDBManager->deleteDB("db_test");
    dbList = m_spKVDBManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 0);
}

TEST_F(KVDBTest, DeleteDataBaseWithRestart)
{
    m_spKVDBManager->createDB("db_test");
    auto dbList = m_spKVDBManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 1);
    ASSERT_EQ(dbList[0], "db_test");
    auto createResult = m_spKVDBManager->createDB("db_test");
    ASSERT_FALSE(createResult.has_value());
    m_spKVDBManager->deleteDB("db_test");
    dbList = m_spKVDBManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 0);

    try
    {
        m_spKVDBManager->finalize();
    }
    catch (const std::exception& e)
    {
        FAIL() << "Exception: " << e.what();
    }

    m_spKVDBManager.reset();
    ASSERT_EQ(m_spKVDBManager.use_count(), 0);

    std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();

    kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};
    m_spKVDBManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    m_spKVDBManager->initialize();

    dbList = m_spKVDBManager->listDBs(true);
    ASSERT_EQ(dbList.size(), 0);
}

TEST_F(KVDBTest, ScopeTest)
{
    ASSERT_FALSE(m_spKVDBManager->createDB("test_db"));
    auto resultHandler = m_spKVDBManager->getKVDBHandler("test_db", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->add("key1");
    ASSERT_TRUE(result == std::nullopt);

    auto result1 = handler->contains("key1");
    ASSERT_TRUE(std::holds_alternative<bool>(result1));

    auto result2 = handler->set("key1", "value");
    ASSERT_TRUE(result2 == std::nullopt);

    auto result3 = handler->get("key1");
    ASSERT_TRUE(std::holds_alternative<std::string>(result3));
    ASSERT_EQ(std::get<std::string>(result3), "value");
}

TEST_F(KVDBTest, ScopeInfoEmpty)
{
    auto scopeInfo = m_spKVDBManager->getKVDBScopesInfo();
    ASSERT_EQ(scopeInfo.size(), 0);
}

TEST_F(KVDBTest, ScopeInfoSingle)
{
    auto scopeInfo = m_spKVDBManager->getKVDBScopesInfo();
    ASSERT_EQ(scopeInfo.size(), 0);
}

TEST_F(KVDBTest, ScopeInfoSingleOneHandler)
{
    m_spKVDBManager->createDB("db_test");
    auto handler = m_spKVDBManager->getKVDBHandler("db_test", "scope1");
    auto scopeInfo = m_spKVDBManager->getKVDBScopesInfo();
    ASSERT_EQ(scopeInfo.size(), 1);
}

TEST_F(KVDBTest, DumpOkValidateOrder)
{
    ASSERT_FALSE(m_spKVDBManager->createDB("test_db"));
    auto resultHandler = m_spKVDBManager->getKVDBHandler("test_db", "scope1");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    for (auto i = 1; i <= 10; i++)
    {
        auto result = handler->set(fmt::format("key{0}", i), fmt::format("value{0}", i));
        ASSERT_EQ(result, std::nullopt);
    }

    const auto resultDump = handler->dump(1, 10);

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultDump));
    const auto& result = std::get<std::list<std::pair<std::string, std::string>>>(resultDump);

    auto i = 1, key10 = 0;
    for (auto& [key, value] : result)
    {
        std::cout << key << " : " << value << std::endl;
        if (i == 2 && key10 == 0)
        {
            ASSERT_EQ(key, "key10");
            ASSERT_EQ(value, "value10");
            key10 = 1;
        }
        else
        {
            ASSERT_EQ(key, fmt::format("key{0}", i));
            ASSERT_EQ(value, fmt::format("value{0}", i));
            i++;
        }
    }
}

TEST_F(KVDBTest, DumpWihoutKeys)
{
    ASSERT_FALSE(m_spKVDBManager->createDB("test_db"));
    auto resultHandler = m_spKVDBManager->getKVDBHandler("test_db", "scope1");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    const auto resultDump = handler->dump(1, 100);

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultDump));
    const auto& result = std::get<std::list<std::pair<std::string, std::string>>>(resultDump);

    ASSERT_EQ(result.size(), 0);
}

TEST_P(DumpWithMultiplePages, Functionality)
{
    auto [inserts, page, records, expected] = GetParam();

    ASSERT_FALSE(m_spKVDBManager->createDB("test_db"));
    auto resultHandler = m_spKVDBManager->getKVDBHandler("test_db", "scope1");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    for (auto i = 0; i < inserts; i++)
    {
        auto result = handler->set(fmt::format("{0}", i), fmt::format("value {0}", i));
        ASSERT_EQ(result, std::nullopt);
    }

    const auto result = handler->dump(page, records);

    ASSERT_FALSE(std::holds_alternative<base::Error>(result));
    const auto& resultPage = std::get<std::list<std::pair<std::string, std::string>>>(result);
    ASSERT_EQ(resultPage.size(), expected);
}

INSTANTIATE_TEST_SUITE_P(KVDB,
                         DumpWithMultiplePages,
                         ::testing::Values(std::make_tuple(50, 1, 5, 5),
                                           std::make_tuple(50, 5, 5, 5),
                                           std::make_tuple(30, 3, 5, 5),
                                           std::make_tuple(30, 5, 7, 2),
                                           std::make_tuple(10, 2, 9, 1),
                                           std::make_tuple(50, 2, 50, 0),
                                           std::make_tuple(50, 1, 50, 50),
                                           std::make_tuple(3, 1, 2, 2),
                                           std::make_tuple(3, 3, 50, 0)));

} // namespace

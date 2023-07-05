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

class KVDBTest : public ::testing::Test
{

protected:
    std::shared_ptr<kvdbManager::KVDBManager> m_spKVDBManager;
    std::string kvdbPath;

    void SetUp() override
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
    };

    void TearDown() override
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
    };

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

} // namespace

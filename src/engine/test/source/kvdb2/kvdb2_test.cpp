#include <filesystem>
#include <gtest/gtest.h>
#include <kvdb2/kvdbManager.hpp>
#include <kvdb2/kvdbExcept.hpp>
#include <testsCommon.hpp>

#include <metrics/metricsManager.hpp>

using namespace metricsManager;

namespace
{

const std::string KVDB_PATH {"/tmp/kvdbTestSuitePath/"};
const std::string KVDB_DB_FILENAME {"TEST_DB"};

class KVDB2Test : public ::testing::Test
{

protected:
    std::shared_ptr<kvdbManager::KVDBManager> m_spKVDBManager;

    void SetUp() override
    {
        initLogging();

        // cleaning directory in order to start without garbage.
        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }

        std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();

        kvdbManager::KVDBManagerOptions kvdbManagerOptions { KVDB_PATH, KVDB_DB_FILENAME };

        m_spKVDBManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

        m_spKVDBManager->initialize();
    };

    void TearDown() override
    {
        try
        {
            m_spKVDBManager->finalize();
        }
        catch (kvdbManager::KVDBException& e)
        {
            FAIL() << "KVDBException: " << e.what();
        }

        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }
    };

    void dumpScopeInfo(std::map<std::string, kvdbManager::RefInfo>  & scopeInfo)
    {
        for (auto& scope : scopeInfo)
        {
            std::cout << fmt::format("Scope: {}", scope.first) << std::endl;
            for (auto& handler : scope.second)
            {
                std::cout << fmt::format("Handler: {}", handler.first) << std::endl;
            }
        }
    }
};

TEST_F(KVDB2Test, Startup)
{
    ASSERT_NE(m_spKVDBManager, nullptr);
}

TEST_F(KVDB2Test, ScopeTest)
{
    auto scope = m_spKVDBManager->getKVDBScope("scope1");
    auto handler = scope->getKVDBHandler("db_test");
    auto result = handler->add("key1");
    ASSERT_TRUE(std::holds_alternative<bool>(result));

    auto result1 = handler->contains("key1");
    ASSERT_TRUE(std::holds_alternative<bool>(result1));

    auto result2 = handler->set("key1", "value");
    ASSERT_TRUE(std::holds_alternative<bool>(result2));

    auto result3 = handler->get("key1");
    ASSERT_TRUE(std::holds_alternative<std::string>(result3));
    ASSERT_EQ(std::get<std::string>(result3), "value");
}


TEST_F(KVDB2Test, ScopeInfoEmpty)
{
    auto scope = m_spKVDBManager->getKVDBScope("scope1");
    auto scopeInfo = m_spKVDBManager->getKVDBScopesInfo();
    ASSERT_EQ(scopeInfo.size(), 0);
}

TEST_F(KVDB2Test, ScopeInfoSingle)
{
    auto scope = m_spKVDBManager->getKVDBScope("scope1");
    auto scopeInfo = m_spKVDBManager->getKVDBScopesInfo();
    dumpScopeInfo(scopeInfo);
    ASSERT_EQ(scopeInfo.size(), 0);
}

TEST_F(KVDB2Test, ScopeInfoSingleOneHandler)
{
    auto scope = m_spKVDBManager->getKVDBScope("scope1");
    auto handler = scope->getKVDBHandler("db_test");
    auto scopeInfo = m_spKVDBManager->getKVDBScopesInfo();
    dumpScopeInfo(scopeInfo);
    ASSERT_EQ(scopeInfo.size(), 1);
}

} // namespace

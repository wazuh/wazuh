#include <filesystem>
#include <gtest/gtest.h>
#include <kvdb2/kvdbManager.hpp>
#include <testsCommon.hpp>

#include <metrics/metricsManager.hpp>

using namespace metricsManager;

namespace
{

const std::string KVDB_PATH {"/tmp/kvdbTestSuitePath/"};
const std::string KVDB_DB_FILENAME {"testDB"};

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
    };

    void TearDown() override
    {
        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }
    };
};

TEST_F(KVDB2Test, Startup)
{

}

} // namespace

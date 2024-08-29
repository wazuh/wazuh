#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <random>
#include <thread>
#include <unistd.h>

#include "fakeMetric.hpp"
#include <base/json.hpp>
#include <base/logging.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <kvdb/kvdbManager.hpp>

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

class DumpWithMultiplePages
    : public ::testing::TestWithParam<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t>>
{
private:
    std::string kvdbPath;

protected:
    std::shared_ptr<kvdbManager::IKVDBManager> m_kvdbManager;

    void SetUp() override
    {
        kvdbPath = uniquePath(KVDB_PATH);
        ::Setup(kvdbPath);

        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};

        m_kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, metricsManager);

        m_kvdbManager->initialize();
    }

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

class KVDBHandlerTest : public ::testing::Test
{
private:
    std::string kvdbPath;

protected:
    std::shared_ptr<kvdbManager::IKVDBManager> m_kvdbManager;

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

TEST_F(KVDBHandlerTest, AddKey)
{
    ASSERT_FALSE(m_kvdbManager->createDB("AddKey"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("AddKey", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultAdd = handler->add("key1");
    ASSERT_TRUE(resultAdd == std::nullopt);

    auto resultContains = handler->contains("key1");
    ASSERT_TRUE(std::holds_alternative<bool>(resultContains));
    ASSERT_TRUE(std::get<bool>(resultContains));
}

TEST_F(KVDBHandlerTest, SetKeyWithStringValue)
{
    ASSERT_FALSE(m_kvdbManager->createDB("SetKeyWithStringValue"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("SetKeyWithStringValue", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultAdd = handler->set("key1", "value");
    ASSERT_TRUE(resultAdd == std::nullopt);
}

TEST_F(KVDBHandlerTest, SetKeyWithJsonValue)
{
    ASSERT_FALSE(m_kvdbManager->createDB("SetKeyWithJsonValue"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("SetKeyWithJsonValue", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    json::Json jsonValue {R"({
        "fieldString": "value",
        "fieldIntNumber": 1,
        "fieldDoubleNumber": 69.007,
        "fieldObject": {"field": "value"},
        "fieldArray": ["value"],
        "fieldNull": null,
        "fieldTrue": true,
        "fieldFalse": false
    })"};

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultAdd = handler->set("key1", jsonValue);
    ASSERT_TRUE(resultAdd == std::nullopt);
}

TEST_F(KVDBHandlerTest, ContainsKeyWithoutValue)
{
    ASSERT_FALSE(m_kvdbManager->createDB("ContainsKeyWithoutValue"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("ContainsKeyWithoutValue", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultAdd = handler->add("key1");
    ASSERT_TRUE(resultAdd == std::nullopt);

    auto resultContains = handler->contains("key1");
    ASSERT_TRUE(std::holds_alternative<bool>(resultContains));
    ASSERT_TRUE(std::get<bool>(resultContains));

    resultContains = handler->contains("unknow_key");
    ASSERT_TRUE(std::holds_alternative<bool>(resultContains));
    ASSERT_FALSE(std::get<bool>(resultContains));
}

TEST_F(KVDBHandlerTest, ContainsKeyWithValue)
{
    ASSERT_FALSE(m_kvdbManager->createDB("ContainsKeyWithValue"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("ContainsKeyWithValue", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultAdd = handler->set("key1", "value");
    ASSERT_TRUE(resultAdd == std::nullopt);

    auto resultContains = handler->contains("key1");
    ASSERT_TRUE(std::holds_alternative<bool>(resultContains));
    ASSERT_TRUE(std::get<bool>(resultContains));

    resultContains = handler->contains("unknow_key");
    ASSERT_TRUE(std::holds_alternative<bool>(resultContains));
    ASSERT_FALSE(std::get<bool>(resultContains));
}

TEST_F(KVDBHandlerTest, GetKeyWithValue)
{
    ASSERT_FALSE(m_kvdbManager->createDB("GetKeyWithValue"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("GetKeyWithValue", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultSet = handler->set("key1", "value");
    ASSERT_TRUE(resultSet == std::nullopt);

    auto resultGet = handler->get("key1");
    ASSERT_TRUE(std::holds_alternative<std::string>(resultGet));
    ASSERT_EQ(std::get<std::string>(resultGet), "value");
}

TEST_F(KVDBHandlerTest, GetKeyWithoutValue)
{
    ASSERT_FALSE(m_kvdbManager->createDB("GetKeyWithoutValue"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("GetKeyWithoutValue", "scope1");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto resultAdd = handler->add("key1");
    ASSERT_TRUE(resultAdd == std::nullopt);

    auto resultGet = handler->get("key1");
    ASSERT_TRUE(std::holds_alternative<std::string>(resultGet));
    ASSERT_EQ(std::get<std::string>(resultGet), "");
}

TEST_F(KVDBHandlerTest, DumpOkValidateOrder)
{
    ASSERT_FALSE(m_kvdbManager->createDB("DumpOkValidateOrder"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("DumpOkValidateOrder", "scope1");
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

TEST_F(KVDBHandlerTest, DumpWihoutKeys)
{
    ASSERT_FALSE(m_kvdbManager->createDB("DumpWihoutKeys"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("DumpWihoutKeys", "scope1");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    const auto resultDump = handler->dump(1, 100);

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultDump));
    const auto& result = std::get<std::list<std::pair<std::string, std::string>>>(resultDump);

    ASSERT_EQ(result.size(), 0);
}

TEST_P(DumpWithMultiplePages, Dump)
{
    auto [inserts, page, records, expected] = GetParam();

    ASSERT_FALSE(m_kvdbManager->createDB("DumpWithMultiplePages"));
    auto resultHandler = m_kvdbManager->getKVDBHandler("DumpWithMultiplePages", "scope1");
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
                                           std::make_tuple(30, 5, 6, 6),
                                           std::make_tuple(10, 2, 9, 1),
                                           std::make_tuple(50, 2, 50, 0),
                                           std::make_tuple(50, 1, 50, 50),
                                           std::make_tuple(3, 1, 2, 2),
                                           std::make_tuple(3, 3, 50, 0)));

} // namespace

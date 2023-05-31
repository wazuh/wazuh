#include <filesystem>
#include <gtest/gtest.h>
#include <kvdb/kvdbManager.hpp>
#include <kvdb/kvdbScope.hpp>
#include <testsCommon.hpp>

#include <api/kvdb/handlers.hpp>
#include <metrics/metricsManager.hpp>

using namespace api::kvdb::handlers;
using namespace metricsManager;

namespace
{

const std::string KVDB_PATH {"/tmp/kvdbTestSuitePath/"};
const std::string KVDB_DB_FILENAME {"TEST_DB"};

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

class KVDBApiTest : public ::testing::Test
{

protected:
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;

    void SetUp() override
    {
        initLogging();

        // cleaning directory in order to start without garbage.
        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }

        std::shared_ptr<IMetricsManager> spMetrics = std::make_shared<MetricsManager>();

        kvdbManager::KVDBManagerOptions kvdbManagerOptions {KVDB_PATH, KVDB_DB_FILENAME};

        kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

        kvdbManager->initialize();
    };

    void TearDown() override
    {
        kvdbManager->finalize();

        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }
    };

    api::wpRequest getWRequest(const bool& mustBeLoaded)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setBool(mustBeLoaded, "/mustBeLoaded");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }

    api::wpRequest commonWRequest(const std::string& kvdbName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }

    api::wpRequest commonWRequest()
    {
        // create request
        json::Json data {};
        data.setObject();
        return api::wpRequest::create(rCommand, rOrigin, data);
    }

    api::wpRequest dbWRequest(const std::string& kvdbName, const std::string& keyName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(keyName, "/key");

        return api::wpRequest::create(rCommand, rOrigin, data);
    }

    api::wpRequest dbWRequest(const std::string& kvdbName, const std::string& keyName, const std::string& keyValue)
    {
        // create request
        json::Json data {};
        json::Json entry {};
        data.setObject();
        data.setString(kvdbName, "/name");
        entry.setObject();
        entry.setString(keyName, "/key");
        entry.setString(keyValue, "/value");
        data.set("/entry", entry);

        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(KVDBApiTest, startup)
{
    ASSERT_NE(kvdbManager, nullptr);
}

TEST_F(KVDBApiTest, managerGetOk)
{
    ASSERT_NO_THROW(managerGet(KVDBApiTest::kvdbManager));
}

TEST_F(KVDBApiTest, managerGet)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerGet(KVDBApiTest::kvdbManager));
    const auto response = cmd(getWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["default"]})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerGetWitMultipleDBsLoaded)
{
    api::Handler cmd;

    kvdbManager->getKVDBHandler("test2", "test");

    ASSERT_NO_THROW(cmd = managerGet(KVDBApiTest::kvdbManager));
    const auto response = cmd(getWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["default", "test2"]})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostOk)
{
    ASSERT_NO_THROW(managerPost(KVDBApiTest::kvdbManager));
}

TEST_F(KVDBApiTest, managerPostNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest());
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostNameEmpty)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(""));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"/name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPost)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest("test1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostDBExists)
{
    api::Handler cmd;

    kvdbManager->createDB("test1");

    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest("test1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The Database already exists."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDeleteOk)
{
    ASSERT_NO_THROW(managerDelete(KVDBApiTest::kvdbManager));
}

TEST_F(KVDBApiTest, managerDeleteNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest());
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDeleteNameEmpty)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(""));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"/name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDelete)
{
    api::Handler cmd;
    kvdbManager->createDB("test1");
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest("test1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDeleteDBNotExists)
{
    api::Handler cmd;
    kvdbManager->createDB("test2");
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest("test1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The DB not exists."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDumpOk)
{
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(managerDump(KVDBApiTest::kvdbManager, kvdbScope));
}

TEST_F(KVDBApiTest, managerDumpNameMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = managerDump(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(commonWRequest());
    const auto expectedData = json::Json {R"({"status":"ERROR","entries":[],"error":"Missing /name"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDumpNameEmpty)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = managerDump(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(commonWRequest(""));
    const auto expectedData = json::Json {R"({"status":"ERROR","entries":[],"error":"Field /name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDump)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = managerDump(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(commonWRequest("default"));
    const auto expectedData = json::Json {R"({"status":"OK","entries":[]})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetOk)
{
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(dbGet(KVDBApiTest::kvdbManager, kvdbScope));
}

TEST_F(KVDBApiTest, dbGetNameArrayNotString)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":["TEST_DB_2"]})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetNameMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetNameEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(KVDBApiTest, dbGetKeyMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":"test"})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /key"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetKeyEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", ""));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /key is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetOneKey)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "\"value1\"");

    ASSERT_FALSE(std::holds_alternative<base::Error>(result));

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":"value1"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetRepeatKeyNoError)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "\"\"");

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":""})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("default", "key1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetMoreThanOneKey)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "\"\"");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result));
    auto result2 = handler->set("key2", "\"\"");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result2));

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":""})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("default", "key2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetKeyDBNotExists)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "\"\"");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result));

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default2", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The DB not exists."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetOneKeyNotExists)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "keyNotExists"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Cannot get key ''. Error: keyNotExists"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOk)
{
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
}

TEST_F(KVDBApiTest, dbDeleteNameMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteNameArrayNotString)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":["TEST_DB_2"]})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteNameEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteKeyMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":"test"})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /key"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteKeyEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", ""));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /key is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOneKey)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result));

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteRepeatKeyNoError)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result));

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("default", "key1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteMoreThanOneKey)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result));
    auto result2 = handler->set("key2", "");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result2));

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("default", "key2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteKeyDBNotExists)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");
    auto resultHandler = kvdbScope->getKVDBHandler("default");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "");
    ASSERT_FALSE(std::holds_alternative<base::Error>(result));

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default2", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The DB not exists."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOneKeyNotExists)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "keyNotExists"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutOk)
{
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(dbPut(KVDBApiTest::kvdbManager, kvdbScope));
}

TEST_F(KVDBApiTest, dbPutNameArrayNotString)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":["TEST_DB_2"]})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutNameMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"entry":{"key":"key1","value":"value1"}})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutNameEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutKeyMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":"test","entry":{"value":"value1"}})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /entry/key"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutKeyEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "", "value1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /key is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutValueMissing)
{
    api::Handler cmd;
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    json::Json params {R"({"name":"test","entry":{"key":"key1"}})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /entry/value"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutValueEmpty)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1", ""));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutOneKey)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutRepeatKeyNoError)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("default", "key1", "value1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutMoreThanOneKey)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("default", "key2", "value2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutKeyDBNotExists)
{
    api::Handler cmd;

    auto kvdbScope = kvdbManager->getKVDBScope("test");

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, kvdbScope));
    const auto response = cmd(dbWRequest("default2", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The DB not exists."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, registerHandlers)
{
    auto api = std::make_shared<api::Api>();
    auto kvdbScope = kvdbManager->getKVDBScope("test");
    ASSERT_NO_THROW(registerHandlers(KVDBApiTest::kvdbManager, kvdbScope, api));
}

} // namespace

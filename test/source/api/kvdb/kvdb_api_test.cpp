#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

#include <api/kvdb/handlers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <metrics/metricsManager.hpp>
#include <testsCommon.hpp>

using namespace api::kvdb::handlers;
using namespace metricsManager;

namespace
{

const std::string KVDB_PATH {"/tmp/kvdbTestSuitePath/"};
const std::string KVDB_DB_FILENAME {"TEST_DB"};
const std::string KVDB_TEST_1 {"test1"};
const std::string KVDB_TEST_2 {"test2"};
const std::string JSON_FILE_WITH_VALUE_OK {"/tmp/kvdb_with_value.json"};
const std::string JSON_FILE_WITHOUT_VALUE_OK {"/tmp/kvdb_without_value.json"};
const std::string JSON_FILE_NOK {"/tmp/kvdb_nok.json"};
const std::string JSON_FILE_NOT_EXISTS {"/tmp/kvdb_not_exists.json"};

const std::string rawValueKeyA;
const std::string valueKeyA {fmt::format("\"{}\"", rawValueKeyA)};
const int rawValueKeyB {69};
const std::string valueKeyB {fmt::format("{}", rawValueKeyB)};
const std::string rawValueKeyCA {"valueCA"};
const std::string rawValueKeyCB {"valueCB"};
const std::string rawValueKeyCC {"valueCC"};
const std::string valueKeyC {fmt::format("[\"{}\",\"{}\",\"{}\"]", rawValueKeyCA, rawValueKeyCB, rawValueKeyCC)};
const std::string rawValueKeyDA {"valueDA"};
const int rawValueKeyDB {666};
const int rawValueKeyDC0 {10};
const int rawValueKeyDC1 {7};
const int rawValueKeyDC2 {1992};
const std::string valueKeyD {fmt::format("{{\"keyDA\":\"{}\",\"keyDB\":{},\"keyDC\":[{},{},{}]}}",
                                         rawValueKeyDA,
                                         rawValueKeyDB,
                                         rawValueKeyDC0,
                                         rawValueKeyDC1,
                                         rawValueKeyDC2)};

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

class KVDBApiTest : public ::testing::Test
{

protected:
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
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

        kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

        kvdbManager->initialize();

        createJsonFileWithoutValueOK();
        createJsonFileNOK();
    };

    void TearDown() override
    {
        kvdbManager->finalize();

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }
    };

    void createJsonFileWithValueOK()
    {
        if (std::filesystem::exists(JSON_FILE_WITH_VALUE_OK))
        {
            std::filesystem::remove(JSON_FILE_WITH_VALUE_OK);
        }
        std::ofstream file(JSON_FILE_WITH_VALUE_OK);
        if (file.is_open())
        {
            file << fmt::format("{{\n\t\"keyA\": {},\n\t\"keyB\": {},\n"
                                "\t\"keyC\": {},\n\t\"keyD\": {}\n}}",
                                valueKeyA,
                                valueKeyB,
                                valueKeyC,
                                valueKeyD);
            file.close();
        }
    }

    void createJsonFileWithoutValueOK()
    {
        if (std::filesystem::exists(JSON_FILE_WITHOUT_VALUE_OK))
        {
            std::filesystem::remove(JSON_FILE_WITHOUT_VALUE_OK);
        }
        std::ofstream file(JSON_FILE_WITHOUT_VALUE_OK);

        if (file.is_open())
        {
            file << R"({
                        "keyA":"",
                        "keyB":"",
                        "keyC":""
                    })";
            file.close();
        }
    }

    void createJsonFileNOK()
    {
        if (std::filesystem::exists(JSON_FILE_NOK))
        {
            std::filesystem::remove(JSON_FILE_NOK);
        }
        std::ofstream file(JSON_FILE_NOK);

        if (file.is_open())
        {
            file << R"(raw text)";
            file.close();
        }
    }

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

    api::wpRequest commonWRequest(const std::string& kvdbName, const std::string& jsonFile)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(jsonFile, "/path");
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
    const auto expectedData = json::Json {R"({"status":"OK","dbs":[]})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerGetWitMultipleDBsLoaded)
{
    api::Handler cmd;

    kvdbManager->createDB(KVDB_TEST_2);
    kvdbManager->getKVDBHandler(KVDB_TEST_2, "test");

    ASSERT_NO_THROW(cmd = managerGet(KVDBApiTest::kvdbManager));
    const auto response = cmd(getWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["test2"]})"};

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
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /name can not be empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPost)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonWithValueOK)
{
    api::Handler cmd;
    createJsonFileWithValueOK();
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, JSON_FILE_WITH_VALUE_OK));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonWithoutValueOK)
{
    api::Handler cmd;
    createJsonFileWithoutValueOK();
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, JSON_FILE_WITHOUT_VALUE_OK));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithPathEmpty)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, {""}));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"The DB was created but loading data returned: The path is empty."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonPathNotExists)
{
    api::Handler cmd;
    createJsonFileNOK();
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, JSON_FILE_NOT_EXISTS));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"The DB was created but loading data returned: An error occurred while opening the file '/tmp/kvdb_not_exists.json'"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonNOK)
{
    api::Handler cmd;
    createJsonFileNOK();
    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, JSON_FILE_NOK));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"The DB was created but loading data returned: An error occurred while parsing the JSON file '/tmp/kvdb_nok.json'"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostDBExists)
{
    api::Handler cmd;

    kvdbManager->createDB(KVDB_TEST_1);

    ASSERT_NO_THROW(cmd = managerPost(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1));
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
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDelete)
{
    api::Handler cmd;
    kvdbManager->createDB(KVDB_TEST_1);
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDeleteDBNotExists)
{
    api::Handler cmd;
    kvdbManager->createDB(KVDB_TEST_2);
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB test1 does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDeleteDBInUse)
{
    api::Handler cmd;
    ASSERT_FALSE(kvdbManager->createDB("test2"));
    auto handler = kvdbManager->getKVDBHandler("test2", "test");
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<kvdbManager::IKVDBHandler>>(handler));
    ASSERT_NO_THROW(cmd = managerDelete(KVDBApiTest::kvdbManager));
    const auto response = cmd(commonWRequest("test2"));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"Could not remove the DB 'test2'. Usage Reference Count: 1."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDumpOk)
{
    ASSERT_NO_THROW(managerDump(KVDBApiTest::kvdbManager, "test"));
}

TEST_F(KVDBApiTest, managerDumpNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = managerDump(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(commonWRequest(""));
    const auto expectedData = json::Json {R"({"status":"ERROR","entries":[],"error":"Field /name cannot be empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDump)
{
    api::Handler cmd;
    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = managerDump(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(commonWRequest("test_db"));
    const auto expectedData = json::Json {R"({"status":"OK","entries":[]})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetOk)
{
    ASSERT_NO_THROW(dbGet(KVDBApiTest::kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbGetNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_FALSE(kvdbManager->createDB("test"));
    auto resultHandler = kvdbManager->getKVDBHandler("test", "test");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "\"value1\"");
    ASSERT_FALSE(result);

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":"value1"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetRepeatKeyNoError)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "\"\"");
    ASSERT_FALSE(result);
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":""})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test_db", "key1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetMoreThanOneKey)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "\"\"");
    ASSERT_FALSE(result);
    auto result2 = handler->set("key2", "\"\"");
    ASSERT_FALSE(result2);

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":""})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test_db", "key2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetKeyDBNotExists)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "\"\"");
    ASSERT_FALSE(result);

    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("default2", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB 'default2' does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetOneKeyNotExists)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbGet(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "keyNotExists"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Cannot get key ''. Error: keyNotExists"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOk)
{
    ASSERT_NO_THROW(dbDelete(KVDBApiTest::kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbDeleteNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "");
    ASSERT_FALSE(result);

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteRepeatKeyNoError)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    auto result = handler->set("key1", "");
    ASSERT_FALSE(result);

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test_db", "key1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteMoreThanOneKey)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "");
    ASSERT_FALSE(result);
    auto result2 = handler->set("key2", "");
    ASSERT_FALSE(result2);

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test_db", "key2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteKeyDBNotExists)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    auto resultHandler = kvdbManager->getKVDBHandler("test_db", "test");
    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));
    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
    auto result = handler->set("key1", "");
    ASSERT_FALSE(result);

    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("default2", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB default2 does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOneKeyNotExists)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbDelete(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "keyNotExists"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutOk)
{
    ASSERT_NO_THROW(dbPut(KVDBApiTest::kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbPutNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
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

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1", ""));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutOneKey)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutRepeatKeyNoError)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test_db", "key1", "value1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutMoreThanOneKey)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test_db", "key2", "value2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutKeyDBNotExists)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = dbPut(KVDBApiTest::kvdbManager, "test"));
    const auto response = cmd(dbWRequest("default2", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB default2 does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, registerHandlers)
{
    auto api = std::make_shared<api::Api>();
    ASSERT_NO_THROW(registerHandlers(KVDBApiTest::kvdbManager, "test", api));
}

} // namespace

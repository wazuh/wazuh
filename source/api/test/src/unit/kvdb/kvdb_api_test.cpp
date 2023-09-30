#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include <api/kvdb/handlers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <metrics/metricsManager.hpp>

#include "../../apiAuxiliarFunctions.hpp"

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

std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
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

    kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, spMetrics);

    kvdbManager->initialize();
}

void TearDown()
{
    kvdbManager->finalize();

    if (std::filesystem::exists(kvdbPath))
    {
        std::filesystem::remove_all(kvdbPath);
    }
}

api::wpRequest dbSearchWRequest(const std::string& kvdbName, const std::string& prefix)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(kvdbName, "/name");
    data.setString(prefix, "/prefix");

    return api::wpRequest::create(rCommand, rOrigin, data);
}

class DumpWithMultiplePages : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    void SetUp() override { ::Setup(); }

    void TearDown() override { ::TearDown(); };
};

class DumpParameters : public DumpWithMultiplePages
{
protected:
    void SetUp() override { ::Setup(); }

    void TearDown() override { ::TearDown(); };
};

class DbSearchTestParameters : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    void SetUp() override { ::Setup(); }

    void TearDown() override { ::TearDown(); };
};

class DbSearchTestFuncionality : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    void SetUp() override { ::Setup(); }

    void TearDown() override { ::TearDown(); };
};

class KVDBApiTest : public ::testing::Test
{

protected:
    void SetUp() override
    {
        ::Setup();

        createJsonFileWithoutValueOK();
        createJsonFileNOK();
    };

    void TearDown() override { ::TearDown(); };

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
    ASSERT_NO_THROW(managerGet(kvdbManager));
}

TEST_F(KVDBApiTest, managerGet)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerGet(kvdbManager));
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

    ASSERT_NO_THROW(cmd = managerGet(kvdbManager));
    const auto response = cmd(getWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["test2"]})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostOk)
{
    ASSERT_NO_THROW(managerPost(kvdbManager));
}

TEST_F(KVDBApiTest, managerPostNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
    const auto response = cmd(commonWRequest(""));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Field /name is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPost)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, {""}));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"Field /path is empty"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonPathNotExists)
{
    api::Handler cmd;
    createJsonFileNOK();
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, JSON_FILE_NOT_EXISTS));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"The database could not be created. Error: An error occurred while opening the file '/tmp/kvdb_not_exists.json'"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonNOK)
{
    api::Handler cmd;
    createJsonFileNOK();
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, JSON_FILE_NOK));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"The database could not be created. Error: An error occurred while parsing the JSON file '/tmp/kvdb_nok.json'"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostDBExists)
{
    api::Handler cmd;

    kvdbManager->createDB(KVDB_TEST_1);

    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The Database already exists."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerDeleteOk)
{
    ASSERT_NO_THROW(managerDelete(kvdbManager));
}

TEST_F(KVDBApiTest, managerDeleteNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerDelete(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerDelete(kvdbManager));
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
    ASSERT_NO_THROW(cmd = managerDelete(kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB 'test1' does not exist."})"};

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
    auto handler2 = kvdbManager->getKVDBHandler("test2", "test2");
    auto handler3 = kvdbManager->getKVDBHandler("test2", "test3");

    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<kvdbManager::IKVDBHandler>>(handler));
    ASSERT_NO_THROW(cmd = managerDelete(kvdbManager));
    const auto response = cmd(commonWRequest("test2"));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"Could not remove the DB 'test2'. Usage Reference Count: 3."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_P(DumpParameters, ValidateParameters)
{
    auto [params, expected] = GetParam();
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(kvdbManager, "test"));
    json::Json jsonParams(params.c_str());
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, jsonParams));
    const auto expectedData = json::Json(expected.c_str());

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

INSTANTIATE_TEST_SUITE_P(
    KVDB,
    DumpParameters,
    ::testing::Values(
        std::make_tuple(R"({"page": 0, "records": 0})", R"({"status":"ERROR","entries":[],"error":"Missing /name"})"),
        std::make_tuple(R"({"name": "", "page": 0, "records": 0})",
                        R"({"status":"ERROR","entries":[],"error":"Field /name cannot be empty"})"),
        std::make_tuple(R"({"name": "test", "page": 1, "records": 0})",
                        R"({"status":"ERROR","entries":[],"error":"Field /records must be greater than 0"})"),
        std::make_tuple(R"({"name": "test", "page": 0, "records": 2})",
                        R"({"status":"ERROR","entries":[],"error":"Field /page must be greater than 0"})")));

TEST_P(DumpWithMultiplePages, Functionality)
{
    auto [params, expected] = GetParam();

    api::Handler cmd;
    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = managerDump(kvdbManager, "test"));
    json::Json jsonParams(params.c_str());
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, jsonParams));
    const auto expectedData = json::Json(expected.c_str());

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

INSTANTIATE_TEST_SUITE_P(
    KVDB,
    DumpWithMultiplePages,
    ::testing::Values(
        std::make_tuple(R"({"name": "test_db", "page": 1, "records": 1})", R"({"status":"OK","entries":[]})"),
        std::make_tuple(R"({"name": "test_db", "page": 0, "records": 0})",
                        R"({"status":"ERROR","entries":[],"error":"Field /page must be greater than 0"})"),
        std::make_tuple(R"({"name": "test_db", "page": 1, "records": 10})", R"({"status":"OK","entries":[]})"),
        std::make_tuple(R"({"name": "test_db", "page": 3, "records": 5})", R"({"status":"OK","entries":[]})")));

TEST_F(KVDBApiTest, dbGetOk)
{
    ASSERT_NO_THROW(dbGet(kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbGetNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "keyNotExists"));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"Can not get key 'keyNotExists'. Error: Key not found"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOk)
{
    ASSERT_NO_THROW(dbDelete(kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbDeleteNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("default2", "key1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB 'default2' does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteOneKeyNotExists)
{
    api::Handler cmd;

    ASSERT_FALSE(kvdbManager->createDB("test_db"));
    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test_db", "keyNotExists"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutOk)
{
    ASSERT_NO_THROW(dbPut(kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbPutNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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
    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
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

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("default2", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"The KVDB 'default2' does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, registerHandlers)
{
    auto api = std::make_shared<api::Api>();
    ASSERT_NO_THROW(registerHandlers(kvdbManager, "test", api));
}

TEST_F(KVDBApiTest, dbSearchOk)
{
    ASSERT_NO_THROW(dbSearch(kvdbManager, "test"));
}

TEST_P(DbSearchTestParameters, ValidateParameters)
{
    auto [params, expectedMessage] = GetParam();
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbSearch(kvdbManager, "test"));
    json::Json jsonParams(params.c_str());
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, jsonParams));

    const auto expectedData = json::Json(expectedMessage.c_str());

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

INSTANTIATE_TEST_SUITE_P(
    KVDB,
    DbSearchTestParameters,
    ::testing::Values(
        std::make_tuple(
            R"({"name":["TEST_DB_2"]})",
            R"({"status":"ERROR","entries":[],"error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"),
        std::make_tuple(
            R"({"prefix":["key1"]})",
            R"({"status":"ERROR","entries":[],"error":"INVALID_ARGUMENT:prefix: Proto field is not repeating, cannot start list."})"),
        std::make_tuple(R"({"prefix": "key1"})", R"({"status":"ERROR","entries": [],"error":"Missing /name"})"),
        std::make_tuple(R"({"name":"TEST_DB"})", R"({"status":"ERROR","entries":[],"error":"Missing /prefix"})"),
        std::make_tuple(R"({"name":"", "prefix":"key1"})",
                        R"({"status":"ERROR","entries":[],"error":"Field /name is empty"})"),
        std::make_tuple(R"({"name":"test", "prefix":""})",
                        R"({"status":"ERROR","entries":[],"error":"Field /prefix is empty"})")));

TEST_P(DbSearchTestFuncionality, Functionality)
{
    api::Handler cmd;
    auto [params, expectedValue] = GetParam();
    ASSERT_FALSE(kvdbManager->createDB("test"));
    auto resultHandler = kvdbManager->getKVDBHandler("test", "test");

    ASSERT_FALSE(std::holds_alternative<base::Error>(resultHandler));

    auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

    handler->set("key1", "\"value1\"");
    handler->set("key11", "\"value1\"");
    handler->set("key2", "\"value2\"");
    handler->set("key3", "\"value3\"");
    handler->set("key4", "\"value4\"");
    handler->set("key5", "\"value5\"");

    ASSERT_NO_THROW(cmd = dbSearch(kvdbManager, "test"));
    json::Json jsonParams(params.c_str());
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, jsonParams));
    const auto expectedData = json::Json(expectedValue.c_str());

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

INSTANTIATE_TEST_SUITE_P(
    KVDB,
    DbSearchTestFuncionality,
    ::testing::Values(
        std::make_tuple(
            R"({"name":"test", "prefix":"key1"})",
            R"({"status":"OK","entries":[{"key":"key1","value":"value1"},{"key":"key11","value":"value1"}]})"),
        std::make_tuple(R"({"name":"test", "prefix":"keyx"})", R"({"status":"OK","entries":[]})"),
        std::make_tuple(R"({"name":"default2", "prefix":"keyx"})",
                        R"({"status":"ERROR","entries":[],"error":"The KVDB 'default2' does not exist."})"),
        std::make_tuple(
            R"({"name":"test", "prefix":"key", "page": 1, "records":"5"})",
            R"({"status":"OK","entries":[{"key":"key1","value":"value1"},{"key":"key11","value":"value1"},{"key":"key2","value":"value2"},{"key":"key3","value":"value3"},{"key":"key4","value":"value4"}]})"),
        std::make_tuple(R"({"name":"test", "prefix":"key", "page": 2, "records":"1"})",
                        R"({"status":"OK","entries":[{"key":"key11","value":"value1"}]})"),
        std::make_tuple(R"({"name":"test", "prefix":"key", "page": 2, "records":"2"})",
                        R"({"status":"OK","entries":[{"key":"key2","value":"value2"},{"key":"key3","value":"value3"}]})")));

} // namespace

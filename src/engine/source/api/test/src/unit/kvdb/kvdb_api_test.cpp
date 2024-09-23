#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include <api/kvdb/handlers.hpp>
#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/mockKvdbManager.hpp>

using namespace api::kvdb::handlers;
using namespace kvdb::mocks;

namespace
{
const std::string KVDB_TEST_1 {"test1"};
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
    std::shared_ptr<MockKVDBManager> kvdbManager;

    void SetUp() override
    {
        logging::testInit();

        kvdbManager = std::make_shared<MockKVDBManager>();
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    ASSERT_NE(kvdbManager, nullptr);
}

TEST_F(KVDBApiTest, managerGetOk)
{
    ASSERT_NO_THROW(managerGet(kvdbManager));
}

TEST_F(KVDBApiTest, managerGet)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, listDBs(true)).WillOnce(testing::Return(kvdbListDBsEmpty()));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    const std::vector<std::string> expected = {"test2"};
    EXPECT_CALL(*kvdbManager, listDBs(true)).WillOnce(testing::Return(expected));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(false));
    EXPECT_CALL(*kvdbManager, createDB(KVDB_TEST_1)).WillOnce(testing::Return(kvdbOk()));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(false));
    EXPECT_CALL(*kvdbManager, createDB(KVDB_TEST_1, JSON_FILE_WITH_VALUE_OK)).WillOnce(testing::Return(kvdbOk()));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(false));
    EXPECT_CALL(*kvdbManager, createDB(KVDB_TEST_1, JSON_FILE_WITHOUT_VALUE_OK)).WillOnce(testing::Return(kvdbOk()));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, createDB(KVDB_TEST_1, "")).WillOnce(testing::Return(kvdbError("The path is empty.")));
    ASSERT_NO_THROW(cmd = managerPost(kvdbManager));
    const auto response = cmd(commonWRequest(KVDB_TEST_1, {""}));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"The database could not be created. Error: The path is empty."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, managerPostWithJsonPathNotExists)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(false));
    EXPECT_CALL(*kvdbManager, createDB(KVDB_TEST_1, "/tmp/kvdb_not_exists.json"))
        .WillOnce(testing::Return(kvdbError("An error occurred while opening the file '/tmp/kvdb_not_exists.json'")));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(false));
    EXPECT_CALL(*kvdbManager, createDB(KVDB_TEST_1, "/tmp/kvdb_nok.json"))
        .WillOnce(testing::Return(kvdbError("An error occurred while parsing the JSON file '/tmp/kvdb_nok.json'")));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(true));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    ASSERT_NO_THROW(managerDelete(kvdbManager));
}

TEST_F(KVDBApiTest, managerDeleteNameMissing)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(true));
    EXPECT_CALL(*kvdbManager, deleteDB(KVDB_TEST_1)).WillOnce(testing::Return(kvdbOk()));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB(KVDB_TEST_1)).WillOnce(testing::Return(false));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    EXPECT_CALL(*kvdbManager, existsDB("test2")).WillOnce(testing::Return(true));
    EXPECT_CALL(*kvdbManager, deleteDB("test2"))
        .WillOnce(testing::Return(kvdbError("Could not remove the DB 'test2'. Usage Reference Count: 3.")));
    ASSERT_NO_THROW(cmd = managerDelete(kvdbManager));
    const auto response = cmd(commonWRequest("test2"));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"Could not remove the DB 'test2'. Usage Reference Count: 3."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetOk)
{
    ASSERT_NO_THROW(dbGet(kvdbManager, "test"));
}

TEST_F(KVDBApiTest, dbGetNameArrayNotString)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillOnce(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, get(testing::_)).WillOnce(testing::Return(R"("value1")"));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillOnce(testing::Return(kvdbHandler));

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, get(testing::_)).WillRepeatedly(testing::Return(R"("")"));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":""})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test", "key1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetMoreThanOneKey)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, get(testing::_)).WillRepeatedly(testing::Return(R"("")"));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK","value":""})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test", "key2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbGetKeyDBNotExists)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("default2")).WillRepeatedly(testing::Return(false));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillOnce(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, get(testing::_))
        .WillOnce(testing::Return(kvdbGetError("Can not get key 'keyNotExists'. Error: Key not found")));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillOnce(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbGet(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "keyNotExists"));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillOnce(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, remove(testing::_)).WillOnce(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillOnce(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteRepeatKeyNoError)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, remove(testing::_)).WillRepeatedly(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test", "key1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteMoreThanOneKey)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, remove(testing::_)).WillRepeatedly(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test", "key2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbDeleteKeyDBNotExists)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("default2")).WillOnce(testing::Return(false));

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, remove(testing::_)).WillRepeatedly(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbDelete(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "keyNotExists"));
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
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
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillOnce(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, set("key1", R"("")")).WillOnce(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillOnce(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1", ""));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutOneKey)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillOnce(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, set("key1", R"("value1")")).WillOnce(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillOnce(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutRepeatKeyNoError)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, set("key1", R"("value1")")).WillRepeatedly(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    const auto response2 = cmd(dbWRequest("test", "key1", "value1"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutMoreThanOneKey)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, set("key1", R"("value1")")).WillRepeatedly(testing::Return(kvdbOk()));
    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

    ASSERT_NO_THROW(cmd = dbPut(kvdbManager, "test"));
    const auto response = cmd(dbWRequest("test", "key1", "value1"));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);

    EXPECT_CALL(*kvdbHandler, set("key2", R"("value2")")).WillRepeatedly(testing::Return(kvdbOk()));
    const auto response2 = cmd(dbWRequest("test", "key2", "value2"));

    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData);
}

TEST_F(KVDBApiTest, dbPutKeyDBNotExists)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("default2")).WillRepeatedly(testing::Return(false));

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

TEST_F(KVDBApiTest, dbSearchDBNotExists)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    api::HandlerSync cmd;
    json::Json jsonParams(R"({"name":"default2", "prefix": "key"})");
    ASSERT_NO_THROW(cmd = dbSearch(kvdbManager, "test"));
    EXPECT_CALL(*kvdbManager, existsDB("default2")).WillOnce(testing::Return(false));
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, jsonParams));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","entries":[],"error":"The KVDB 'default2' does not exist."})"};

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

template<typename T>
class DumpTest : public ::testing::TestWithParam<T>
{
protected:
    void SetUp() override { logging::testInit(); }
};

using DumpParameters = DumpTest<std::tuple<std::string, std::string>>;

TEST_P(DumpParameters, ValidateParameters)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    auto [params, expected] = GetParam();
    api::HandlerSync cmd;

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

using DumpWithMultiplePages = DumpTest<std::tuple<std::string, std::string>>;

TEST_P(DumpWithMultiplePages, Functionality)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    auto [params, expected] = GetParam();

    api::HandlerSync cmd;

    EXPECT_CALL(*kvdbManager, existsDB("test")).WillRepeatedly(testing::Return(true));

    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, dump(testing::_, testing::_)).WillRepeatedly(testing::Return(kvdbDumpOk()));

    EXPECT_CALL(*kvdbManager, getKVDBHandler("test", "test")).WillRepeatedly(testing::Return(kvdbHandler));

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
        std::make_tuple(R"({"name": "test", "page": 1, "records": 1})", R"({"status":"OK","entries":[]})"),
        std::make_tuple(R"({"name": "test", "page": 0, "records": 0})",
                        R"({"status":"ERROR","entries":[],"error":"Field /page must be greater than 0"})"),
        std::make_tuple(R"({"name": "test", "page": 1, "records": 10})", R"({"status":"OK","entries":[]})"),
        std::make_tuple(R"({"name": "test", "page": 3, "records": 5})", R"({"status":"OK","entries":[]})")));

template<typename T>
class SearchTest : public ::testing::TestWithParam<T>
{
protected:
    void SetUp() override { logging::testInit(); }
};

using SearchTestParameters = SearchTest<std::tuple<std::string, std::string>>;

TEST_P(SearchTestParameters, ValidateParameters)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    auto [params, expectedMessage] = GetParam();
    api::HandlerSync cmd;
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
    SearchTestParameters,
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

// Default expected function
template<typename Ret = base::OptError>
using ExpectedFn = std::function<Ret(std::shared_ptr<MockKVDBManager>, std::shared_ptr<MockKVDBHandler>)>;
using Behaviour = std::function<void(std::shared_ptr<MockKVDBManager>, std::shared_ptr<MockKVDBHandler>)>;

ExpectedFn<> success(Behaviour behaviour = nullptr)
{
    return [behaviour](auto manager, auto handler)
    {
        if (behaviour)
        {
            behaviour(manager, handler);
        }
        return base::noError();
    };
}
ExpectedFn<> failure(Behaviour behaviour = nullptr)
{
    return [behaviour](auto manager, auto handler)
    {
        if (behaviour)
        {
            behaviour(manager, handler);
        }
        return base::Error {};
    };
}

template<typename Ret>
using BehaviourRet =
    std::function<base::RespOrError<Ret>(std::shared_ptr<MockKVDBManager>, std::shared_ptr<MockKVDBHandler>)>;

template<typename Ret>
ExpectedFn<base::RespOrError<Ret>> success(BehaviourRet<Ret> behaviour = nullptr)
{
    return [behaviour](auto store, auto validator) -> base::RespOrError<Ret>
    {
        if (behaviour)
        {
            return behaviour(store, validator);
        }

        return Ret {};
    };
}

template<typename Ret>
ExpectedFn<base::RespOrError<Ret>> failure(Behaviour behaviour = nullptr)
{
    return [behaviour](auto store, auto validator)
    {
        if (behaviour)
        {
            behaviour(store, validator);
        }
        return base::Error {};
    };
}

using SearchT = std::tuple<std::string, ExpectedFn<base::RespOrError<std::string>>>;
using SearchTestFuncionality = SearchTest<SearchT>;

TEST_P(SearchTestFuncionality, Functionality)
{
    auto kvdbManager = std::make_shared<MockKVDBManager>();
    auto kvdbHandler = std::make_shared<MockKVDBHandler>();
    api::HandlerSync cmd;

    auto [params, expectedFn] = GetParam();
    auto expected = expectedFn(kvdbManager, kvdbHandler);

    ASSERT_NO_THROW(cmd = dbSearch(kvdbManager, "test"));
    json::Json jsonParams(params.c_str());
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, jsonParams));
    const auto expectedData = json::Json(base::getResponse<std::string>(expected).c_str());

    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData);
}

INSTANTIATE_TEST_SUITE_P(
    KVDB,
    SearchTestFuncionality,
    ::testing::Values(
        // OK
        SearchT(
            R"({"name": "test", "prefix":"key1"})",
            success<std::string>(
                [](auto manager, auto handler)
                {
                    EXPECT_CALL(*manager, existsDB("test")).WillOnce(testing::Return(true));
                    EXPECT_CALL(*manager, getKVDBHandler("test", "test")).WillOnce(testing::Return(handler));
                    EXPECT_CALL(*handler, search("key1", DEFAULT_HANDLER_PAGE, DEFAULT_HANDLER_RECORDS))
                        .WillOnce(testing::Invoke(
                            [&](const std::string& prefix, const unsigned int page, const unsigned int records)
                            {
                                std::list<std::pair<std::string, std::string>> list;
                                list.emplace_back(std::make_pair("key1", R"("value1")"));
                                list.emplace_back(std::make_pair("key11", R"("value1")"));
                                return list;
                            }));

                    return R"({"status":"OK","entries":[{"key":"key1","value":"value1"},{"key":"key11","value":"value1"}]})";
                })),
        SearchT(R"({"name": "test", "prefix":"keyx"})",
                success<std::string>(
                    [](auto manager, auto handler)
                    {
                        EXPECT_CALL(*manager, existsDB("test")).WillOnce(testing::Return(true));
                        EXPECT_CALL(*manager, getKVDBHandler("test", "test")).WillOnce(testing::Return(handler));
                        EXPECT_CALL(*handler, search("keyx", DEFAULT_HANDLER_PAGE, DEFAULT_HANDLER_RECORDS))
                            .WillOnce(testing::Invoke(
                                [&](const std::string& prefix, const unsigned int page, const unsigned int records)
                                { return std::list<std::pair<std::string, std::string>>(); }));
                        return R"({"status":"OK","entries":[]})";
                    })),
        SearchT(
            R"({"name": "test", "prefix":"key", "page": 1, "records":"5"})",
            success<std::string>(
                [](auto manager, auto handler)
                {
                    EXPECT_CALL(*manager, existsDB("test")).WillOnce(testing::Return(true));
                    EXPECT_CALL(*manager, getKVDBHandler("test", "test")).WillOnce(testing::Return(handler));
                    EXPECT_CALL(*handler, search("key", 1, 5))
                        .WillOnce(testing::Invoke(
                            [&](const std::string& prefix, const unsigned int page, const unsigned int records)
                            {
                                std::list<std::pair<std::string, std::string>> list;
                                list.emplace_back(std::make_pair("key1", R"("value1")"));
                                list.emplace_back(std::make_pair("key11", R"("value1")"));
                                list.emplace_back(std::make_pair("key2", R"("value2")"));
                                list.emplace_back(std::make_pair("key3", R"("value3")"));
                                list.emplace_back(std::make_pair("key4", R"("value4")"));
                                return list;
                            }));
                    return R"({"status":"OK","entries":[{"key":"key1","value":"value1"},{"key":"key11","value":"value1"},{"key":"key2","value":"value2"},{"key":"key3","value":"value3"},{"key":"key4","value":"value4"}]})";
                })),
        SearchT(R"({"name": "test", "prefix":"key", "page": 2, "records":"1"})",
                success<std::string>(
                    [](auto manager, auto handler)
                    {
                        EXPECT_CALL(*manager, existsDB("test")).WillOnce(testing::Return(true));
                        EXPECT_CALL(*manager, getKVDBHandler("test", "test")).WillOnce(testing::Return(handler));
                        EXPECT_CALL(*handler, search("key", 2, 1))
                            .WillOnce(testing::Invoke(
                                [&](const std::string& prefix, const unsigned int page, const unsigned int records)
                                {
                                    std::list<std::pair<std::string, std::string>> list;
                                    list.emplace_back(std::make_pair("key11", R"("value1")"));
                                    return list;
                                }));
                        return R"({"status":"OK","entries":[{"key":"key11","value":"value1"}]})";
                    })),
        SearchT(
            R"({"name": "test", "prefix":"key", "page": 2, "records":"2"})",
            success<std::string>(
                [](auto manager, auto handler)
                {
                    EXPECT_CALL(*manager, existsDB("test")).WillOnce(testing::Return(true));
                    EXPECT_CALL(*manager, getKVDBHandler("test", "test")).WillOnce(testing::Return(handler));
                    EXPECT_CALL(*handler, search("key", 2, 2))
                        .WillOnce(testing::Invoke(
                            [&](const std::string& prefix, const unsigned int page, const unsigned int records)
                            {
                                std::list<std::pair<std::string, std::string>> list;
                                list.emplace_back(std::make_pair("key2", R"("value2")"));
                                list.emplace_back(std::make_pair("key3", R"("value3")"));
                                return list;
                            }));
                    return R"({"status":"OK","entries":[{"key":"key2","value":"value2"},{"key":"key3","value":"value3"}]})";
                }))));
} // namespace

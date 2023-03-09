#include <api/kvdb/commands.hpp>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

using namespace api::kvdb::cmds;

constexpr auto DB_NAME = "TEST_DB";
constexpr auto DB_NAME_2 = "TEST_DB_2";
constexpr auto DB_NAME_3 = "TEST_DB_3";
constexpr auto DB_NAME_WITH_SPACES = "TEST_DB SEPARATE NAME";
constexpr auto DB_NAME_ANOTHER = "ANOTHER_DB_NAME";
constexpr auto DB_DIR = "/tmp/kvdbTestDir/";
constexpr auto FILE_PATH = "/tmp/file";
constexpr auto KEY_A = "keyA";
constexpr auto KEY_B = "keyB";
constexpr auto KEY_C = "keyC";
constexpr auto KEY_D = "keyD";
constexpr auto VAL_A = "valA";

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

const std::string rawValueKeyA {"valueA"};
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

inline void createJsonTestFile(const std::string filePath = FILE_PATH)
{
    // File creation
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << fmt::format("{{\n\t\"keyA\": {},\n\t\"keyB\": {},\n"
                                       "\t\"keyC\": {},\n\t\"keyD\": {}\n}}",
                                       valueKeyA,
                                       valueKeyB,
                                       valueKeyC,
                                       valueKeyD);
            exampleFile.close();
        }
    }
}

inline void createKeyOnlyJsonTestFile(const std::string filePath = FILE_PATH)
{
    // File creation
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << R"({
                                "keyA":"",
                                "keyB":"",
                                "keyC":""
                              })";
            exampleFile.close();
        }
    }
}

// "managerPost" tests section

class managerPost_Handler : public ::testing::Test
{

protected:
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        auto varHandle = kvdbManager->getHandler(DB_NAME, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));
    }

    virtual void TearDown()
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }

    json::Json getParametersInJson(const std::string& kvdbName, const std::string& kvdbInputFilePath = "")
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(kvdbInputFilePath, "/path");
        return data;
    }
};

TEST_F(managerPost_Handler, ok)
{
    ASSERT_NO_THROW(managerPost(managerPost_Handler::kvdbManager));
}

TEST_F(managerPost_Handler, NameMissing)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params {R"({"not_name": "dummyString"})"};
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /name"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, NameNotString)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params {R"({"name": ["dummyString"]})"};
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"ERROR"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, BoolNotString)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params {R"({"name": false})"};
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"ERROR"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, NameNumberNotString)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params {R"({"name": 123})"};
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"ERROR"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, EmptyName)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson("");
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"ERROR"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, SimpleAddition)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson(DB_NAME_2);
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"OK"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, DuplicatedDatabase)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson(DB_NAME_2);
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"OK"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;

    // Add new database with the same name
    const auto response2 = cmd(request);
    const auto expectedData2 = json::Json {R"({"status":"ERROR","error":"Database 'TEST_DB_2' already exists"})"};

    // check response
    ASSERT_TRUE(response2.isValid());
    ASSERT_EQ(response2.error(), 0);
    ASSERT_FALSE(response2.message().has_value());
    ASSERT_EQ(response2.data(), expectedData2) << "Response: " << response2.data().prettyStr() << std::endl
                                               << "Expected: " << expectedData2.prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, NameWithSpaces)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson(DB_NAME_WITH_SPACES);
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"OK"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, WithFilling)
{
    createJsonTestFile();

    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson(DB_NAME_2, FILE_PATH);
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData = std::string {"OK"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data().getString("/status").value_or("Not status in result"), expectedData)
        << "Response: " << response.data().prettyStr() << std::endl;

    // check value
    auto value = kvdbManager->getRawValue(DB_NAME_2, KEY_A);
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyA.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, KEY_B);
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyB.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, KEY_C);
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyC.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, KEY_D);
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyD.c_str(), std::get<std::string>(value).c_str());
}

TEST_F(managerPost_Handler, WithWrongFilling)
{
    // File creation
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << R"({{"keyA": [~] }})";
            exampleFile.close();
        }
    }

    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson(DB_NAME_2, FILE_PATH);
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"An error occurred while parsing the JSON file '/tmp/file'"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerPost_Handler, NonExistingFile)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(managerPost_Handler::kvdbManager));
    json::Json params = getParametersInJson(DB_NAME_2, FILE_PATH);
    api::wpRequest request = api::wpRequest::create(rCommand, rOrigin, params);

    const auto response = cmd(request);
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"An error occurred while opening the file '/tmp/file'"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

// "kvdbDeleteCmd" tests section

class managerDelete_Handler : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_NOT_AVAILABLE = "TEST_DB_NOT_AVAILABLE";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        auto varHandle = kvdbManager->getHandler(DB_NAME, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));
    }

    size_t getNumberOfKVDBLoaded() { return kvdbManager->listDBs().size(); }

    virtual void TearDown() {}

    api::wpRequest deleteWRequest(const std::string& kvdbName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(managerDelete_Handler, ok)
{
    ASSERT_NO_THROW(managerDelete(managerDelete_Handler::kvdbManager));
}

// This can occur when a DB that was used on a decoder is no longer used
TEST_F(managerDelete_Handler, LoadedOnlyOnMap)
{
    // DB_NAME is only loaded on map, it will be unloaded and deleted
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    auto response = cmd(deleteWRequest(DB_NAME));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check remaining available DBs
    ASSERT_EQ(managerDelete_Handler::getNumberOfKVDBLoaded(), 0);
}

TEST_F(managerDelete_Handler, BlockBecauseLoaded)
{
    // DB_NAME is on the loaded map but it needs to be instanced in any helper:
    auto res = managerDelete_Handler::kvdbManager->getHandler(DB_NAME);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdbHandleExample = std::get<kvdb_manager::KVDBHandle>(res);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    auto response = cmd(deleteWRequest(DB_NAME));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check remaining available DBs
    ASSERT_EQ(managerDelete_Handler::getNumberOfKVDBLoaded(), 1);
}

TEST_F(managerDelete_Handler, Success)
{
    // create unloaded DB
    auto resultString = managerDelete_Handler::kvdbManager->createFromJFile(DB_NAME_2);
    ASSERT_FALSE(resultString.has_value());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    auto response = cmd(deleteWRequest(DB_NAME_2));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
}

TEST_F(managerDelete_Handler, DBDoesntExist)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    const auto response = cmd(deleteWRequest(DB_NAME_NOT_AVAILABLE));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    // TODO ERROR

    // check remaining available DBs
    ASSERT_EQ(managerDelete_Handler::getNumberOfKVDBLoaded(), 1);
}

TEST_F(managerDelete_Handler, NameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    json::Json params {R"( { "no_name": "dummy" } )"};
    auto request = api::wpRequest::create(rCommand, rOrigin, params);
    const auto response = cmd(request);

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDelete_Handler, NameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    auto request = api::wpRequest::create(rCommand, rOrigin, params);
    const auto response = cmd(request);

    // check response
    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDelete_Handler, NameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    auto request = api::wpRequest::create(rCommand, rOrigin, params);
    const auto response = cmd(request);

    // check response
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"INVALID_ARGUMENT:(name): invalid value 69 for type TYPE_STRING"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDelete_Handler, EmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(managerDelete_Handler::kvdbManager));
    const auto response = cmd(deleteWRequest(""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Database name is empty"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

// "managerDump" tests section

class managerDump_Handler : public ::testing::Test
{

protected:
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }

        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }

        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        auto varHandle = kvdbManager->getHandler(DB_NAME, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));
    }

    virtual void TearDown() {}

    api::wpRequest dumpWRequest(const std::string& kvdbName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(managerDump_Handler, ok)
{
    ASSERT_NO_THROW(managerDump(managerDump_Handler::kvdbManager));
}

TEST_F(managerDump_Handler, NameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(managerDump_Handler::kvdbManager));
    json::Json params {R"({"dummy_key": "dummy_value"})"};

    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","entries":[],"error":"Missing /name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDump_Handler, NameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(managerDump_Handler::kvdbManager));
    json::Json params {R"({"name": [123]})"};

    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","entries":[],"error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDump_Handler, NameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(managerDump_Handler::kvdbManager));
    json::Json params {R"({"name": 123})"};

    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","entries":[],"error":"INVALID_ARGUMENT:(name): invalid value 123 for type TYPE_STRING"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDump_Handler, EmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(managerDump_Handler::kvdbManager));
    const auto response = cmd(dumpWRequest(""));
    const auto expectedData = json::Json {R"({"status":"ERROR","entries":[],"error":"Database name is empty"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerDump_Handler, SimpleExecution)
{
    // create file with content
    createJsonTestFile();

    auto resultString = managerDump_Handler::kvdbManager->createFromJFile(DB_NAME_2, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(managerDump_Handler::kvdbManager));
    const auto response = cmd(dumpWRequest(DB_NAME_2));
    const auto expectedEntry = json::Json {
        R"([{"value":{"keyDB":666,"keyDA":"valueDA","keyDC":[10,7,1992]},"key":"keyD"},{"key":"keyC","value":["valueCA","valueCB","valueCC"]},{"key":"keyB","value":69},{"key":"keyA","value":"valueA"}])"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());

    // check content
    const auto kvdbContent = response.data().getJson("/entries");
    ASSERT_TRUE(kvdbContent.has_value());
    ASSERT_EQ(kvdbContent.value(), expectedEntry) << "Response: " << kvdbContent.value().prettyStr() << std::endl
                                                  << "Expected: " << expectedEntry.prettyStr() << std::endl;
}

TEST_F(managerDump_Handler, SimpleEmpty)
{

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDump(managerDump_Handler::kvdbManager));
    const auto response = cmd(dumpWRequest(DB_NAME));
    const auto expectedData = json::Json {R"({"status":"OK","entries":[]})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

// "dbGet" tests section
class dbGet_Handler : public ::testing::Test
{

protected:
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        kvdbManager->createFromJFile(DB_NAME);
    }

    virtual void TearDown() {}

    api::wpRequest getWRequest(const std::string& kvdbName, const std::string& keyName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(keyName, "/key");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(dbGet_Handler, ok)
{
    ASSERT_NO_THROW(dbGet(dbGet_Handler::kvdbManager));
}

TEST_F(dbGet_Handler, NameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(dbGet_Handler::kvdbManager));
    json::Json params {R"({"dummy_key": "dummy_value"})"};

    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbGet_Handler, NameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(dbGet_Handler::kvdbManager));
    json::Json params {R"({"name": ["dummy_value"]})"};

    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbGet_Handler, NameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(dbGet_Handler::kvdbManager));
    json::Json params {R"({"name": 66})"};

    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"INVALID_ARGUMENT:(name): invalid value 66 for type TYPE_STRING"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbGet_Handler, EmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(dbGet_Handler::kvdbManager));
    const auto response = cmd(getWRequest("", ""));

    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Database name is empty"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbGet_Handler, EmptyKey)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(dbGet_Handler::kvdbManager));
    const auto response = cmd(getWRequest(DB_NAME, ""));
    const auto expectedData = json::Json {R"( {"status":"ERROR","error":"Empty key or column name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbGet_Handler, SimpleExecutionKeyOnly)
{
    // Insert key
    json::Json VAL_JA {"\"valA\""};
    dbGet_Handler::kvdbManager->writeKey(DB_NAME, KEY_A, VAL_JA);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbGet(dbGet_Handler::kvdbManager));
    const auto response = cmd(getWRequest(DB_NAME, KEY_A));
    const auto expectedData = json::Json {R"({"status":"OK","value":"valA"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

// "dbPut" tests section

class dbPut_Handler : public ::testing::Test
{

protected:
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        kvdbManager->createFromJFile(DB_NAME);
    }

    virtual void TearDown() {}

    api::wpRequest
    insertWRequest(const std::string& kvdbName, const std::string& keyName, const std::string& keyValue = "")
    {
        // create request
        json::Json data {};
        data.setObject();

        data.setString(kvdbName, "/name");
        data.setString(keyName, "/entry/key");
        if (!keyValue.empty())
        {
            data.setString(keyValue, "/entry/value");
        }
        else
        {
            data.setNull("/entry/value");
        }
        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(dbPut_Handler, ok)
{
    ASSERT_NO_THROW(dbPut(dbPut_Handler::kvdbManager));
}

TEST_F(dbPut_Handler, NameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbPut_Handler, NameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json {
        R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbPut_Handler, NameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"INVALID_ARGUMENT:(name): invalid value 69 for type TYPE_STRING"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbPut_Handler, EmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    const auto response = cmd(insertWRequest("", KEY_A));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Database name is empty"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbPut_Handler, EmptyKey)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    const auto response = cmd(insertWRequest(DB_NAME, ""));
    const auto expectedData =
        json::Json {R"({"status":"ERROR","error":"Could not write key '' to database 'TEST_DB'"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbPut_Handler, SimpleExecutionKeyOnly)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    const auto response = cmd(insertWRequest(DB_NAME, KEY_A));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;

    auto value = dbPut_Handler::kvdbManager->getJValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<json::Json>(value));
    ASSERT_EQ(std::get<json::Json>(value), json::Json {"null"});
}

TEST_F(dbPut_Handler, SimpleExecutionKeyValue)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbPut(dbPut_Handler::kvdbManager));
    const auto response = cmd(insertWRequest(DB_NAME, KEY_A, rawValueKeyA));
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;

    auto value = dbPut_Handler::kvdbManager->getJValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<json::Json>(value));
    ASSERT_EQ(std::get<json::Json>(value).getString().value_or("INVALID"), rawValueKeyA);
}

// "managerGet" tests section

class managerGet_Handler : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_DIFFERENT_START = "NOT_TEST_DB";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        auto varHandle = kvdbManager->getHandler(DB_NAME, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));
    }

    virtual void TearDown() {}

    api::wpRequest listWRequest(const bool& mustBeLoaded)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setBool(mustBeLoaded, "/mustBeLoaded");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(managerGet_Handler, ok)
{
    ASSERT_NO_THROW(managerGet(managerGet_Handler::kvdbManager));
}

TEST_F(managerGet_Handler, SingleDBLoaded)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerGet(managerGet_Handler::kvdbManager));
    const auto response = cmd(listWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["TEST_DB"]})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerGet_Handler, NoneLoaded)
{
    // Deletes the only DB from the list
    managerGet_Handler::kvdbManager->unloadDB(DB_NAME);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerGet(managerGet_Handler::kvdbManager));
    const auto response = cmd(listWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":[]})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerGet_Handler, MultipleLoaded)
{
    // Adds another DB to the list
    auto varHandle = kvdbManager->getHandler(DB_NAME_2, true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerGet(managerGet_Handler::kvdbManager));
    const auto response = cmd(listWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["TEST_DB_2","TEST_DB"]})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(managerGet_Handler, WithFilteringLoaded)
{
    // add a db wich name starts different than the others
    auto varHandle = kvdbManager->getHandler(DB_NAME_DIFFERENT_START, true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerGet(managerGet_Handler::kvdbManager));
    auto response = cmd(listWRequest(true));
    const auto expectedData = json::Json {R"({"status":"OK","dbs":["NOT_TEST_DB","TEST_DB"]})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

// "dbDelete" tests section
class dbDelete_Handler : public ::testing::Test
{

protected:
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        kvdbManager->createFromJFile(DB_NAME);
        kvdbManager->writeRaw(DB_NAME, KEY_A, VAL_A);
    }

    virtual void TearDown() {}

    api::wpRequest removeWRequest(const std::string& kvdbName, const std::string& keyName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(keyName, "/key");
        return api::wpRequest::create(rCommand, rOrigin, data);
    }
};

TEST_F(dbDelete_Handler, ok)
{
    ASSERT_NO_THROW(dbDelete(dbDelete_Handler::kvdbManager));
}

TEST_F(dbDelete_Handler, NameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    json::Json params {R"({})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                               << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, NameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    json::Json params {R"({"name":["TEST_DB_2"]})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"INVALID_ARGUMENT:name: Proto field is not repeating, cannot start list."})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, EmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    const auto response = cmd(removeWRequest("", KEY_A));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Database name is empty"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, KeyMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    json::Json params {R"({"name":"TEST_DB"})"};
    const auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing /key"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, EmptyKey)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    const auto response = cmd(removeWRequest(DB_NAME, ""));
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Empty key or column name"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, SimpleExecution)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    const auto response = cmd(removeWRequest(DB_NAME, KEY_A));

    const auto expectedData = json::Json {R"({"status":"OK"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;

    auto value = dbDelete_Handler::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<base::Error>(value));
}

TEST_F(dbDelete_Handler, SimpleExecutionDoubleRemoveNoError)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    auto response = cmd(removeWRequest(DB_NAME, KEY_A));

    const auto expectedData = json::Json {R"({"status":"OK"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;

    response = cmd(removeWRequest(DB_NAME, KEY_A));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, RemoveNonExistingDB)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    const auto response = cmd(removeWRequest(DB_NAME_ANOTHER, KEY_A));

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Database 'ANOTHER_DB_NAME' not found or could not be loaded"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(dbDelete_Handler, RemoveReturnsOkWithNonExistingKeyName)
{
    constexpr auto keyName = "ANOTHER_KEY_NAME";
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = dbDelete(dbDelete_Handler::kvdbManager));
    const auto response = cmd(removeWRequest(DB_NAME, keyName));

    // check response
    const auto expectedData = json::Json {R"({"status":"OK"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

// registerHandlers section

TEST(kvdbAPICmdsTest, registerHandlers)
{
    auto kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);

    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(registerHandlers(kvdbManager, apiReg));

    ASSERT_NO_THROW(apiReg->getHandler("kvdb.manager/post"));
    ASSERT_NO_THROW(apiReg->getHandler("kvdb.manager/delete"));
    ASSERT_NO_THROW(apiReg->getHandler("kvdb.manager/get"));
    ASSERT_NO_THROW(apiReg->getHandler("kvdb.manager/dump"));
    ASSERT_NO_THROW(apiReg->getHandler("kvdb.db/put"));
    ASSERT_NO_THROW(apiReg->getHandler("kvdb.db/delete"));
    ASSERT_NO_THROW(apiReg->getHandler("kvdb.db/get"));
}

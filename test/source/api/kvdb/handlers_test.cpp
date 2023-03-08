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

const std::string rCommand {"command to exec"};
const std::string rOrigin {"Origin module"};
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

class kvdbAPICreateHandler : public ::testing::Test
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

TEST_F(kvdbAPICreateHandler, managerPost)
{
    ASSERT_NO_THROW(managerPost(kvdbAPICreateHandler::kvdbManager));
}

TEST_F(kvdbAPICreateHandler, managerPostNameMissing)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostNameNotString)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostBoolNotString)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostNameNumberNotString)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostEmptyName)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostSimpleAddition)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostDuplicatedDatabase)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostNameWithSpaces)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostWithFilling)
{
    createJsonTestFile();

    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostWithWrongFilling)
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

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

TEST_F(kvdbAPICreateHandler, managerPostNonExistingFile)
{
    api::Handler cmd;

    ASSERT_NO_THROW(cmd = managerPost(kvdbAPICreateHandler::kvdbManager));
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

class kvdbAPIDeleteHandler : public ::testing::Test
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

TEST_F(kvdbAPIDeleteHandler, managerDelete)
{
    ASSERT_NO_THROW(managerDelete(kvdbAPIDeleteHandler::kvdbManager));
}

// This can occur when a DB that was used on a decoder is no longer used
TEST_F(kvdbAPIDeleteHandler, managerDeleteLoadedOnlyOnMap)
{
    // DB_NAME is only loaded on map, it will be unloaded and deleted
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
    auto response = cmd(deleteWRequest(DB_NAME));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteHandler::getNumberOfKVDBLoaded(), 0);
}

TEST_F(kvdbAPIDeleteHandler, managerDeleteBlockBecauseLoaded)
{
    // DB_NAME is on the loaded map but it needs to be instanced in any helper:
    auto res = kvdbAPIDeleteHandler::kvdbManager->getHandler(DB_NAME);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdbHandleExample = std::get<kvdb_manager::KVDBHandle>(res);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
    auto response = cmd(deleteWRequest(DB_NAME));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteHandler::getNumberOfKVDBLoaded(), 1);
}

TEST_F(kvdbAPIDeleteHandler, managerDeleteSuccess)
{
    // create unloaded DB
    auto resultString = kvdbAPIDeleteHandler::kvdbManager->createFromJFile(DB_NAME_2);
    ASSERT_FALSE(resultString.has_value());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
    auto response = cmd(deleteWRequest(DB_NAME_2));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
}

TEST_F(kvdbAPIDeleteHandler, managerDeleteDBDoesntExist)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
    const auto response = cmd(deleteWRequest(DB_NAME_NOT_AVAILABLE));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    // TODO ERROR

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteHandler::getNumberOfKVDBLoaded(), 1);
}

TEST_F(kvdbAPIDeleteHandler, managerDeleteNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
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

TEST_F(kvdbAPIDeleteHandler, managerDeleteNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
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

TEST_F(kvdbAPIDeleteHandler, managerDeleteNameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
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

TEST_F(kvdbAPIDeleteHandler, managerDeleteEmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = managerDelete(kvdbAPIDeleteHandler::kvdbManager));
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

// "kvdbDumpCmd" tests section
/*
class kvdbAPIDumpCommand : public ::testing::Test
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

    json::Json getParametersInJson(const std::string& kvdbName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        return data;
    }
};

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmd)
{
    ASSERT_NO_THROW(kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdEmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdSimpleExecution)
{
    // create file with content
    createJsonTestFile();

    auto resultString =
        kvdbAPIDumpCommand::kvdbManager->createFromJFile(DB_NAME_2, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME_2));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("KVDB '{}' successfully dumped", DB_NAME_2).c_str());

    // check content
    const auto kvdbContent = response.data().getArray();
    ASSERT_TRUE(kvdbContent.has_value());
    ASSERT_EQ(kvdbContent.value().size(), 4);

    ASSERT_TRUE(kvdbContent.value().at(0).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(0).getString("/key").value().c_str(), KEY_A);
    ASSERT_TRUE(kvdbContent.value().at(1).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(1).getString("/key").value().c_str(), KEY_B);
    ASSERT_TRUE(kvdbContent.value().at(2).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(2).getString("/key").value().c_str(), KEY_C);
    ASSERT_TRUE(kvdbContent.value().at(3).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(3).getString("/key").value().c_str(), KEY_D);

    ASSERT_TRUE(kvdbContent.value().at(0).getString("/value").has_value());
    ASSERT_STREQ(kvdbContent.value().at(0).getString("/value").value().c_str(),
                 rawValueKeyA.c_str());
    ASSERT_TRUE(kvdbContent.value().at(1).getInt("/value").has_value());
    ASSERT_EQ(kvdbContent.value().at(1).getInt("/value").value(), rawValueKeyB);
    ASSERT_TRUE(kvdbContent.value().at(2).getArray("/value").has_value());
    ASSERT_STREQ(kvdbContent.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(0)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCA.c_str());
    ASSERT_STREQ(kvdbContent.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(1)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCB.c_str());
    ASSERT_STREQ(kvdbContent.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(2)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCC.c_str());
    ASSERT_TRUE(kvdbContent.value().at(3).getObject("/value").has_value());
    ASSERT_STREQ(
        std::get<0>(kvdbContent.value().at(3).getObject("/value").value()[0]).c_str(),
        "keyDA");
    ASSERT_STREQ(
        std::get<0>(kvdbContent.value().at(3).getObject("/value").value()[1]).c_str(),
        "keyDB");
    ASSERT_STREQ(
        std::get<0>(kvdbContent.value().at(3).getObject("/value").value()[2]).c_str(),
        "keyDC");
    ASSERT_TRUE(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[0])
                    .getString()
                    .has_value());
    ASSERT_STREQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[0])
                     .getString()
                     .value()
                     .c_str(),
                 rawValueKeyDA.c_str());
    ASSERT_TRUE(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[1])
                    .getInt()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[1])
                  .getInt()
                  .value(),
              rawValueKeyDB);
    ASSERT_TRUE(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                    .getArray()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(0)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC0);
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(1)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC1);
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(2)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC2);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdSimpleEmpty)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("KVDB '{}' successfully dumped", DB_NAME).c_str());

    auto dataArray = response.data().getArray();
    ASSERT_EQ(dataArray.value().size(), 0);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdKVDBOnlyKeys)
{
    // create file with content
    createKeyOnlyJsonTestFile();

    const auto resultString =
        kvdbAPIDumpCommand::kvdbManager->createFromJFile(DB_NAME_2, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME_2));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("KVDB '{}' successfully dumped", DB_NAME_2).c_str());

    // check content
    const auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 3);

    ASSERT_TRUE(kvdbList.value().at(0).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(0).getString("/key").value().c_str(), KEY_A);
    ASSERT_TRUE(kvdbList.value().at(1).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(1).getString("/key").value().c_str(), KEY_B);
    ASSERT_TRUE(kvdbList.value().at(2).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(2).getString("/key").value().c_str(), KEY_C);

    ASSERT_TRUE(kvdbList.value().at(0).getString("/value").has_value());
    ASSERT_STREQ(kvdbList.value().at(0).getString("/value").value().c_str(), "");
    ASSERT_TRUE(kvdbList.value().at(1).getString("/value").has_value());
    ASSERT_STREQ(kvdbList.value().at(1).getString("/value").value().c_str(), "");
    ASSERT_TRUE(kvdbList.value().at(2).getString("/value").has_value());
    ASSERT_STREQ(kvdbList.value().at(2).getString("/value").value().c_str(), "");
}

// "kvdbGetKeyCmd" tests section

class kvdbAPIGetCommand : public ::testing::Test
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

    json::Json getParametersInJson(const std::string& kvdbName,
                                   const std::string& keyName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(keyName, "/key");
        return data;
    }
};

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmd)
{
    ASSERT_NO_THROW(kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdEmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    const auto response = cmd(getParametersInJson("", ""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_MISSING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": [\"dummy_key\"]}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"key\": 69}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdEmptyKey)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, ""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIGetCommand, SimpleExecutionKeyOnly)
{
    // Insert key
    json::Json VAL_JA {"\"valA\""};
    kvdbAPIGetCommand::kvdbManager->writeKey(DB_NAME, KEY_A, VAL_JA);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // compare content
    auto data = response.data().getString("/value");
    ASSERT_TRUE(data.has_value());
    ASSERT_EQ(data.value(), VAL_A);
}

// "kvdbInsertKeyCmd" tests section

class kvdbAPIInsertCommand : public ::testing::Test
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

    json::Json getParametersInJson(const std::string& kvdbName,
                                   const std::string& keyName,
                                   const std::string& keyValue = "")
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(keyName, "/key");
        if (!keyValue.empty())
        {
            data.setString(keyValue, "/value");
        }
        return data;
    }
};

TEST_F(kvdbAPIInsertCommand, kvdbAPIInsertCommand)
{
    ASSERT_NO_THROW(kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdEmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    const auto response = cmd(getParametersInJson("", ""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_MISSING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": [\"dummy_key\"]}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"key\": 69}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdEmptyKey)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, ""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyOnly)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 "Key-value successfully written to the database");

    // get key and compare content
    auto value = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<std::string>(value));
    ASSERT_EQ(std::get<std::string>(value), "null");
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyValue)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, KEY_A, rawValueKeyA));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 "Key-value successfully written to the database");

    // get key and compare content
    auto value = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_STREQ(std::get<std::string>(value).c_str(), valueKeyA.c_str());
}

TEST_F(kvdbAPIInsertCommand, ExecutionOKSeveralKeys)
{
    std::vector<std::string> severalKeys = {"1",
                                            "A",
                                            "b",
                                            "!#$%&'()*+,-./",
                                            "0123456789",
                                            ":;<=>?@",
                                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                                            "[^_`abcdefghijklmnopqrstuvwxyz{|}~"};
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& key : severalKeys)
    {
        const auto response = cmd(getParametersInJson(DB_NAME, key));

        // check response
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 0);
        ASSERT_TRUE(response.message().has_value());
        ASSERT_STREQ(response.message().value().c_str(),
                     "Key-value successfully written to the database");

        // get key and compare content
        auto value = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, key);
        ASSERT_EQ(std::get<std::string>(value), "null");
    }
}

TEST_F(kvdbAPIInsertCommand, ExecutionOKSeveralValues)
{
    std::vector<std::string> severalValues = {"1",
                                              "A",
                                              "b",
                                              "!#$%&'()*+,-./",
                                              "0123456789",
                                              ":;<=>?@",
                                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                                              "[^_`bcdefghijklmnopqrstuvwxyz{|}~"};
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& value : severalValues)
    {
        const auto response = cmd(getParametersInJson(DB_NAME, KEY_A, value));

        // check response
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 0);
        ASSERT_TRUE(response.message().has_value());
        ASSERT_STREQ(response.message().value().c_str(),
                     "Key-value successfully written to the database");

        // get key and compare content
        auto rawValue = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
        ASSERT_STREQ(std::get<std::string>(rawValue).c_str(),
                     fmt::format("\"{}\"", value).c_str());
    }
}

TEST_F(kvdbAPIInsertCommand, ExecutionWrongDBName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME_ANOTHER, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Key-value could not be written to the database: Database "
                             "'{}' not found or could not be loaded",
                             DB_NAME_ANOTHER)
                     .c_str());
}

// "kvdbListCmd" tests section

class kvdbAPIListCommand : public ::testing::Test
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

    json::Json getParametersInJson(const bool& mustBeLoaded,
                                   const std::string& kvdbName = "")
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setBool(mustBeLoaded, "/mustBeLoaded");
        data.setString(kvdbName, "/name");
        return data;
    }
};

TEST_F(kvdbAPIListCommand, kvdbListCmd)
{
    ASSERT_NO_THROW(kvdbListCmd(kvdbAPIListCommand::kvdbManager));
}

TEST_F(kvdbAPIListCommand, kvdbListCmdSingleDBLoaded)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(true));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check response
    const auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME);
}

TEST_F(kvdbAPIListCommand, kvdbListCmdNoneLoaded)
{
    // Deletes the only DB from the list
    kvdbAPIListCommand::kvdbManager->unloadDB(DB_NAME);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(true));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check response
    const auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 0);
}

TEST_F(kvdbAPIListCommand, kvdbListCmdMultipleLoaded)
{
    // Adds another DB to the list
    auto varHandle = kvdbManager->getHandler(DB_NAME_2, true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(true));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check response
    const auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME_2);
    ASSERT_EQ(kvdbList.value().at(1).getString().value(), DB_NAME);
}

TEST_F(kvdbAPIListCommand, kvdbListCmdWithFilteringLoaded)
{
    // add a db wich name starts different than the others
    auto varHandle = kvdbManager->getHandler(DB_NAME_DIFFERENT_START, true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(varHandle));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    auto response = cmd(getParametersInJson(true, "NOT"));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check response with different name filtered
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME_DIFFERENT_START);

    // same procces filtering with previous name start
    response = cmd(getParametersInJson(true, "TEST_"));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    response = cmd(getParametersInJson(true));
    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(1).getString().value(), DB_NAME);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME_DIFFERENT_START);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    response = cmd(getParametersInJson(true, "wrong_match"));
    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 0);
}

// "kvdbRemoveKeyCmd" tests section

class kvdbAPIRemoveCommand : public ::testing::Test
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

    json::Json getParametersInJson(const std::string& kvdbName,
                                   const std::string& keyName)
    {
        // create request
        json::Json data {};
        data.setObject();
        data.setString(kvdbName, "/name");
        data.setString(keyName, "/key");
        return data;
    }
};

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmd)
{
    ASSERT_NO_THROW(kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdEmptyName)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdKeyMissing)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_MISSING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdKeyArrayNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": [\"dummy_key\"]}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdKeyNumberNotString)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"key\": 69}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdEmptyKey)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, ""));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecution)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "ok");

    auto value = kvdbAPIRemoveCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<base::Error>(value));
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecutionDoubleRemoveNoError)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    auto response = cmd(getParametersInJson(DB_NAME, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "ok");

    response = cmd(getParametersInJson(DB_NAME, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "ok");
}

TEST_F(kvdbAPIRemoveCommand, RemoveNonExistingDB)
{
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME_ANOTHER, KEY_A));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Database '{}' not found or could not be loaded", DB_NAME_ANOTHER).c_str());
}

TEST_F(kvdbAPIRemoveCommand, RemoveReturnsOkWithNonExistingKeyName)
{
    constexpr auto keyName = "ANOTHER_KEY_NAME";
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    const auto response = cmd(getParametersInJson(DB_NAME, keyName));

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "ok");
}

// registerHandlers section

TEST(kvdbAPICmdsTest, registerHandlers)
{
    auto kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);

    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(registerHandlers(kvdbManager, apiReg));

    ASSERT_NO_THROW(apiReg->getHandler("create_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("create_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("delete_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("dump_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("get_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("insert_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("list_kvdb"));
    ASSERT_NO_THROW(apiReg->getHandler("remove_kvdb"));
}
*/

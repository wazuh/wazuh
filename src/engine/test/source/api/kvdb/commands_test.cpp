#include <api/kvdb/commands.hpp>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

using namespace api::kvdb::cmds;

constexpr auto DB_NAME = "TEST_DB";
constexpr auto DB_NAME_2 = "TEST_DB_2";
constexpr auto DB_NAME_3 = "TEST_DB_3";
constexpr auto DB_NAME_WITH_SPACES = "TEST_DB SEPARATE NAME";
constexpr auto DB_DIR = "/tmp/kvdbTestDir/";
constexpr auto FILE_PATH = "/tmp/file";

// Values should be as compact as possible (do not leave spaces nor newlines, etc)
const std::string rawValueKeyA {"valueA"};
const std::string valueKeyA {fmt::format("\"{}\"", rawValueKeyA)};
const int rawValueKeyB {69};
const std::string valueKeyB {fmt::format("{}", rawValueKeyB)};
const std::string rawValueKeyCA {"valueCA"};
const std::string rawValueKeyCB {"valueCB"};
const std::string rawValueKeyCC {"valueCC"};
const std::string valueKeyC {
    fmt::format("[\"{}\",\"{}\",\"{}\"]", rawValueKeyCA, rawValueKeyCB, rawValueKeyCC)};
const std::string rawValueKeyDA {"valueDA"};
const int rawValueKeyDB {666};
const int rawValueKeyDC0 {10};
const int rawValueKeyDC1 {7};
const int rawValueKeyDC2 {1992};
const std::string valueKeyD {
    fmt::format("{{\"keyDA\":\"{}\",\"keyDB\":{},\"keyDC\":[{},{},{}]}}",
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

// "kvdbCreateCmd" tests section

class kvdbAPICreateCommand : public ::testing::Test
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
        kvdbManager->loadDB(DB_NAME);
    }

    virtual void TearDown()
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }
};

TEST_F(kvdbAPICreateCommand, kvdbCreateCmd)
{
    ASSERT_NO_THROW(kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"not_name\": \"dummyString\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummyName\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdSimpleAddition)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdEmptyParams)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdDuplicatedDatabase)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Database '{}' is loaded", DB_NAME).c_str());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameWithSpaces)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_WITH_SPACES).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdWithFilling)
{
    createJsonTestFile();

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check value
    auto value = kvdbManager->getRawValue(DB_NAME_2, "keyA");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyA.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyB");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyB.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyC");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyC.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyD");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyD.c_str(), std::get<std::string>(value).c_str());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdWithWrongFilling)
{
    createJsonTestFile();

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check value
    auto value = kvdbManager->getRawValue(DB_NAME_2, "keyA");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyA.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyB");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyB.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyC");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyC.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyD");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyD.c_str(), std::get<std::string>(value).c_str());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdSingleValueFile)
{
    createJsonTestFile();

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check value
    auto value = kvdbManager->getRawValue(DB_NAME_2, "keyA");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyA.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyB");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyB.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyC");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyC.c_str(), std::get<std::string>(value).c_str());

    value = kvdbManager->getRawValue(DB_NAME_2, "keyD");
    ASSERT_FALSE(std::holds_alternative<base::Error>(value));
    ASSERT_STREQ(valueKeyD.c_str(), std::get<std::string>(value).c_str());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNonExistingFile)
{
    api::CommandFn cmd;

    ASSERT_NO_THROW(cmd = kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("An error occurred while opening the file '{}'", FILE_PATH)
                     .c_str());
}

// "kvdbDeleteCmd" tests section

class kvdbAPIDeleteCommand : public ::testing::Test
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
        kvdbManager->loadDB(DB_NAME);
    }

    size_t getNumberOfKVDBLoaded() { return kvdbManager->listDBs().size(); }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmd)
{
    ASSERT_NO_THROW(kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
}

// This can occur when a DB that was used on a decoder is no longer used
TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdLoadedOnlyOnMap)
{
    // DB_NAME is only loaded on map, it will be unloaded and deleted
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 0);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdBlockBecauseLoaded)
{
    // DB_NAME is on the loaded map but it needs to be instanced in any helper:
    auto kvdbHandleExample = kvdbAPIDeleteCommand::kvdbManager->getDB(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 1);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdSuccess)
{
    // create unloaded DB
    auto resultString =
        kvdbAPIDeleteCommand::kvdbManager->CreateFromJFile(DB_NAME_2);
    ASSERT_FALSE(resultString.has_value());

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdDBDoesntExist)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", DB_NAME_NOT_AVAILABLE).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(
        response.message().value().c_str(),
        fmt::format("Database '{}' not found or could not be loaded.", DB_NAME_NOT_AVAILABLE)
            .c_str());

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 1);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

// "kvdbDumpCmd" tests section

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
        kvdbManager->loadDB(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmd)
{
    ASSERT_NO_THROW(kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameMissing)
{
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

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
        kvdbAPIDumpCommand::kvdbManager->CreateFromJFile(DB_NAME_2, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check content
    const auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 4);

    ASSERT_TRUE(kvdbList.value().at(0).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(0).getString("/key").value().c_str(), "keyA");
    ASSERT_TRUE(kvdbList.value().at(1).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(1).getString("/key").value().c_str(), "keyB");
    ASSERT_TRUE(kvdbList.value().at(2).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(2).getString("/key").value().c_str(), "keyC");
    ASSERT_TRUE(kvdbList.value().at(3).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(3).getString("/key").value().c_str(), "keyD");

    ASSERT_TRUE(kvdbList.value().at(0).getString("/value").has_value());
    ASSERT_STREQ(kvdbList.value().at(0).getString("/value").value().c_str(),
                 rawValueKeyA.c_str());
    ASSERT_TRUE(kvdbList.value().at(1).getInt("/value").has_value());
    ASSERT_EQ(kvdbList.value().at(1).getInt("/value").value(), rawValueKeyB);
    ASSERT_TRUE(kvdbList.value().at(2).getArray("/value").has_value());
    ASSERT_STREQ(kvdbList.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(0)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCA.c_str());
    ASSERT_STREQ(kvdbList.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(1)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCB.c_str());
    ASSERT_STREQ(kvdbList.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(2)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCC.c_str());
    ASSERT_TRUE(kvdbList.value().at(3).getObject("/value").has_value());
    ASSERT_STREQ(
        std::get<0>(kvdbList.value().at(3).getObject("/value").value()[0]).c_str(),
        "keyDA");
    ASSERT_STREQ(
        std::get<0>(kvdbList.value().at(3).getObject("/value").value()[1]).c_str(),
        "keyDB");
    ASSERT_STREQ(
        std::get<0>(kvdbList.value().at(3).getObject("/value").value()[2]).c_str(),
        "keyDC");
    ASSERT_TRUE(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[0])
                    .getString()
                    .has_value());
    ASSERT_STREQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[0])
                     .getString()
                     .value()
                     .c_str(),
                 rawValueKeyDA.c_str());
    ASSERT_TRUE(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[1])
                    .getInt()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[1])
                  .getInt()
                  .value(),
              rawValueKeyDB);
    ASSERT_TRUE(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                    .getArray()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(0)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC0);
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(1)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC1);
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(2)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC2);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdSimpleEmpty)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    auto dataArray = response.data().getArray();
    ASSERT_EQ(dataArray.value().size(),0);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdKVDBOnlyKeys)
{
    // create file with content
    createJsonTestFile();

    const auto resultString =
        kvdbAPIDumpCommand::kvdbManager->CreateFromJFile(DB_NAME_2, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check content
    const auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 4);

    ASSERT_TRUE(kvdbList.value().at(0).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(0).getString("/key").value().c_str(), "keyA");
    ASSERT_TRUE(kvdbList.value().at(1).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(1).getString("/key").value().c_str(), "keyB");
    ASSERT_TRUE(kvdbList.value().at(2).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(2).getString("/key").value().c_str(), "keyC");
    ASSERT_TRUE(kvdbList.value().at(3).getString("/key").has_value());
    ASSERT_STREQ(kvdbList.value().at(3).getString("/key").value().c_str(), "keyD");

    ASSERT_TRUE(kvdbList.value().at(0).getString("/value").has_value());
    ASSERT_STREQ(kvdbList.value().at(0).getString("/value").value().c_str(),
                 rawValueKeyA.c_str());
    ASSERT_TRUE(kvdbList.value().at(1).getInt("/value").has_value());
    ASSERT_EQ(kvdbList.value().at(1).getInt("/value").value(), rawValueKeyB);
    ASSERT_TRUE(kvdbList.value().at(2).getArray("/value").has_value());
    ASSERT_STREQ(kvdbList.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(0)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCA.c_str());
    ASSERT_STREQ(kvdbList.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(1)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCB.c_str());
    ASSERT_STREQ(kvdbList.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(2)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCC.c_str());
    ASSERT_TRUE(kvdbList.value().at(3).getObject("/value").has_value());
    ASSERT_STREQ(
        std::get<0>(kvdbList.value().at(3).getObject("/value").value()[0]).c_str(),
        "keyDA");
    ASSERT_STREQ(
        std::get<0>(kvdbList.value().at(3).getObject("/value").value()[1]).c_str(),
        "keyDB");
    ASSERT_STREQ(
        std::get<0>(kvdbList.value().at(3).getObject("/value").value()[2]).c_str(),
        "keyDC");
    ASSERT_TRUE(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[0])
                    .getString()
                    .has_value());
    ASSERT_STREQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[0])
                     .getString()
                     .value()
                     .c_str(),
                 rawValueKeyDA.c_str());
    ASSERT_TRUE(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[1])
                    .getInt()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[1])
                  .getInt()
                  .value(),
              rawValueKeyDB);
    ASSERT_TRUE(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                    .getArray()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(0)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC0);
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(1)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC1);
    ASSERT_EQ(std::get<1>(kvdbList.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(2)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC2);
}

// "kvdbGetKeyCmd" tests section

class kvdbAPIGetCommand : public ::testing::Test
{

protected:
    static constexpr auto KEY_A = "keyA";
    static constexpr auto VAL_A = "valA";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        kvdbManager->CreateFromJFile(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmd)
{
    ASSERT_NO_THROW(kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameMissing)
{
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyMissing)
{
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIGetCommand, SimpleExecutionKeyOnly)
{
    //Insert key
    json::Json VAL_JA {"\"valA\""};
    kvdbAPIGetCommand::kvdbManager->writeKey(DB_NAME, KEY_A, VAL_JA);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format(R"({{"name": "{}", "key": "{}"}})", DB_NAME, KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // compare content
    auto data = response.data().getString("/value");
    ASSERT_TRUE(data.has_value());
    ASSERT_EQ(data.value(), VAL_A);
}

// "kvdbInsertKeyCmd" tests section

class kvdbAPIInsertCommand : public ::testing::Test
{

protected:
    static constexpr auto KEY_A = "keyA";
    static constexpr auto VAL_A = "valA";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        kvdbManager->CreateFromJFile(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIInsertCommand, kvdbAPIInsertCommand)
{
    ASSERT_NO_THROW(kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameMissing)
{
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyMissing)
{
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyOnly)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // get key and compare content
    auto value = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<std::string>(value));
    ASSERT_EQ(std::get<std::string>(value), "null");
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyValue)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"valA\"}}",
                    DB_NAME,
                    KEY_A)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // get key and compare content
    auto value = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_STREQ(std::get<std::string>(value).c_str(), params.str("/value").value_or("error").c_str());
}

TEST_F(kvdbAPIInsertCommand, ExecutionEmptyValue)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format(
            "{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"\"}}", DB_NAME, KEY_A)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // get key and compare content
    auto value = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_STREQ(std::get<std::string>(value).c_str(), params.str("/value").value_or("error").c_str());
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& key : severalKeys)
    {
        json::Json params {
            fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, key).c_str()};
        const auto response = cmd(params);

        // check response
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 0);
        ASSERT_TRUE(response.message().has_value());
        ASSERT_STREQ(response.message().value().c_str(), "OK");

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
                                              "[^_`\\\"bcdefghijklmnopqrstuvwxyz{|}~"};
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& value : severalValues)
    {
        json::Json params {
            fmt::format("{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"{}\"}}",
                        DB_NAME,
                        KEY_A,
                        value)
                .c_str()};
        const auto response = cmd(params);

        // check response
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 0);
        ASSERT_TRUE(response.message().has_value());
        ASSERT_STREQ(response.message().value().c_str(), "OK");

        // get key and compare content
        auto rawValue = kvdbAPIInsertCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
        ASSERT_STREQ(std::get<std::string>(rawValue).c_str(), params.str("/value").value_or("error").c_str());
    }
}

TEST_F(kvdbAPIInsertCommand, ExecutionWrongDBName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"ANOTHER_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 "Key-value could not be written to the database:Database "
                 "'ANOTHER_DB_NAME' not found or could not be loaded.");
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
        kvdbManager->loadDB(DB_NAME, false);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIListCommand, kvdbListCmd)
{
    ASSERT_NO_THROW(kvdbListCmd(kvdbAPIListCommand::kvdbManager));
}

TEST_F(kvdbAPIListCommand, kvdbListCmdSingleDBLoaded)
{
    // add DB to loaded list
    kvdbManager->loadDB(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    const auto response = cmd(params);
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

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    const auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check response
    const auto kvdbList = response.data().getArray();
    ASSERT_FALSE(kvdbList.has_value());
}

TEST_F(kvdbAPIListCommand, kvdbListCmdMultipleLoaded)
{
    // Adds another DB to the list
    kvdbAPIListCommand::kvdbManager->loadDB(DB_NAME);
    kvdbAPIListCommand::kvdbManager->loadDB(DB_NAME_2);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    const auto response = cmd(params);
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
    // Adds DB to the list
    kvdbAPIListCommand::kvdbManager->loadDB(DB_NAME);
    // add a db wicha name starts different than the others
    kvdbAPIListCommand::kvdbManager->loadDB(DB_NAME_DIFFERENT_START);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params_with_name_not {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"NOT\"}}").c_str()};
    auto response = cmd(params_with_name_not);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    // check response with different name filtered
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME_DIFFERENT_START);

    // same procces filtering with previous name start
    json::Json params_with_name_test {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"TEST_\"}}").c_str()};
    response = cmd(params_with_name_test);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);

    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    json::Json params_with_empty_name {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"\"}}").c_str()};
    response = cmd(params_with_empty_name);
    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(1).getString().value(), DB_NAME);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME_DIFFERENT_START);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    json::Json params_with_wrong_name {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"wrong_match\"}}").c_str()};
    response = cmd(params_with_wrong_name);
    kvdbList = response.data().getArray();
    ASSERT_FALSE(kvdbList.has_value());
}

// "kvdbRemoveKeyCmd" tests section

class kvdbAPIRemoveCommand : public ::testing::Test
{

protected:
    static constexpr auto KEY_A = "keyA";
    static constexpr auto VAL_A = "valA";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);
        kvdbManager->CreateFromJFile(DB_NAME);
        kvdbManager->writeRaw(DB_NAME, KEY_A, VAL_A);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmd)
{
    ASSERT_NO_THROW(kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameMissing)
{
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
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
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecution)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    auto value = kvdbAPIRemoveCommand::kvdbManager->getRawValue(DB_NAME, KEY_A);
    ASSERT_TRUE(std::holds_alternative<base::Error>(value));
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecutionDoubleRemoveNoError)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),"OK");
}

TEST_F(kvdbAPIRemoveCommand, RemoveNonExistingDB)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"ANOTHER_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Database 'ANOTHER_DB_NAME' not found or could not be loaded.").c_str());
}

TEST_F(kvdbAPIRemoveCommand, RemoveReturnsOkWithNonExistingKeyName)
{
    constexpr auto keyName = "ANOTHER_KEY_NAME";
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, keyName).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),"OK");
}

// registerAllCmds section

TEST(kvdbAPICmdsTest, RegisterAllCmds)
{
    auto kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(DB_DIR);

    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(registerAllCmds(kvdbManager, apiReg));

    ASSERT_NO_THROW(apiReg->getCallback("create_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("create_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("delete_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("dump_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("get_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("insert_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("list_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("remove_kvdb"));
}

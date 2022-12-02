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

// "kvdbCreateCmd" tests section

class kvdbAPICreateCommand : public ::testing::Test
{

protected:
    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
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
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"not_name\": \"dummyString\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummyName\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdSimpleAddition)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdEmptyParams)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdDuplicatedDatabase)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("[{}] Database is in use", DB_NAME).c_str());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNameWithSpaces)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_WITH_SPACES).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdWithFilling)
{
    // file creation
    // TODO: replicate with jsons
    GTEST_SKIP();
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA:valueA\n";
            exampleFile << "keyB:valueB\n";
            exampleFile.close();
        }
    }

    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check value
    auto handle = kvdbManager->getDB(DB_NAME_2);
    if (!handle)
    {
        kvdbManager->loadDB(DB_NAME_2, false);
    }
    handle = kvdbManager->getDB(DB_NAME_2);
    ASSERT_TRUE(handle);
    ASSERT_STREQ("valueA", handle->read("keyA").value().c_str());
    ASSERT_STREQ("valueB", handle->read("keyB").value().c_str());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdWithWrongFilling)
{
    // file creation
    // TODO: replicate with jsons
    GTEST_SKIP();
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA-valueA\n";
            exampleFile << "keyB,valueB\n";
            exampleFile.close();
        }
    }

    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check value
    auto handle = kvdbManager->getDB(DB_NAME_2);
    if (!handle)
    {
        kvdbManager->loadDB(DB_NAME_2, false);
    }
    handle = kvdbManager->getDB(DB_NAME_2);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(handle->read("keyA").has_value());
    ASSERT_FALSE(handle->read("keyB").has_value());
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdSingleValueFile)
{
    // file creation
    // TODO: replicate with jsons
    GTEST_SKIP();

    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA\n";
            exampleFile << "keyB\n";
            exampleFile.close();
        }
    }

    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check value
    auto handle = kvdbManager->getDB(DB_NAME_2);
    if (!handle)
    {
        kvdbManager->loadDB(DB_NAME_2, false);
    }
    handle = kvdbManager->getDB(DB_NAME_2);
    ASSERT_TRUE(handle);
    ASSERT_TRUE(handle->hasKey("keyA"));
    ASSERT_TRUE(handle->hasKey("keyB"));
}

TEST_F(kvdbAPICreateCommand, kvdbCreateCmdNonExistingFile)
{
    api::CommandFn cmd;
    // TODO: replicate with jsons
    GTEST_SKIP();

    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbCreateCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}", DB_NAME_2, FILE_PATH)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("[{}] File \"{}\" could not be opened", DB_NAME_2, FILE_PATH)
                     .c_str());
}

// "kvdbDeleteCmd" tests section

class kvdbAPIDeleteCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_NOT_AVAILABLE = "TEST_DB_NOT_AVAILABLE";

    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
        kvdbManager->loadDB(DB_NAME);
    }

    size_t getNumberOfKVDBLoaded() { return kvdbManager->listDBs().size(); }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
}

// TODO: Can we split this test into different tests?
TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdBlockBecauseLoaded)
{
    // can't delete loaded DB
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 1);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdSuccess)
{
    // create unloaded DB
    auto resultString =
        kvdbAPIDeleteCommand::kvdbManager->CreateAndFillDBfromFile(DB_NAME_2);
    ASSERT_STREQ(resultString.c_str(), "OK");

    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdDoesntExist)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", DB_NAME_NOT_AVAILABLE).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(
        response.message().value().c_str(),
        fmt::format("Database \"{}\" could not be deleted", DB_NAME_NOT_AVAILABLE)
            .c_str());

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 1);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDeleteCommand, kvdbDeleteCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbDeleteCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

// "kvdbDumpCmd" tests section

class kvdbAPIDumpCommand : public ::testing::Test
{

protected:
    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }

        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }

        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
        kvdbManager->loadDB(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdSimpleExecution)
{
    // create file with content
    // TODO: replicate with jsons
    GTEST_SKIP();
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA:ValA\n";
            exampleFile << "keyB:ValB\n";
            exampleFile.close();
        }
    }
    auto resultString =
        kvdbAPIDumpCommand::kvdbManager->CreateAndFillDBfromFile(DB_NAME_2, FILE_PATH);
    ASSERT_STREQ(resultString.c_str(), "OK");

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check content
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(0).getString("/value").value(), "ValA");
    ASSERT_EQ(kvdbList.value().at(1).getString("/value").value(), "ValB");
    ASSERT_EQ(kvdbList.value().at(0).getString("/key").value(), "keyA");
    ASSERT_EQ(kvdbList.value().at(1).getString("/key").value(), "keyB");
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdSimpleEmpty)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    auto dataArray = response.data().getArray();
    ASSERT_FALSE(dataArray.has_value());
}

TEST_F(kvdbAPIDumpCommand, kvdbDumpCmdKVDBOnlyKeys)
{
    // create file with content
    // TODO: replicate with jsons
    GTEST_SKIP();
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA\n";
            exampleFile << "keyB\n";
            exampleFile.close();
        }
    }
    auto resultString =
        kvdbAPIDumpCommand::kvdbManager->CreateAndFillDBfromFile(DB_NAME_2, FILE_PATH);
    ASSERT_STREQ(resultString.c_str(), "OK");

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbDumpCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // check content
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(0).getString("/key").value(), "keyA");
    ASSERT_EQ(kvdbList.value().at(1).getString("/key").value(), "keyB");
}

// "kvdbGetKeyCmd" tests section

class kvdbAPIGetCommand : public ::testing::Test
{

protected:
    static constexpr auto KEY_A = "keyA";
    static constexpr auto VAL_A = "valA";

    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
        kvdbManager->CreateAndFillDBfromFile(DB_NAME);
        kvdbManager->writeKey(DB_NAME, KEY_A, VAL_A);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_MISSING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": [\"dummy_key\"]}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdKeyNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"key\": 69}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIGetCommand, kvdbGetKeyCmdEmptyKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIGetCommand, SimpleExecutionKeyOnly)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbGetKeyCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
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

    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
        kvdbManager->CreateAndFillDBfromFile(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIInsertCommand, kvdbAPIInsertCommand)
{
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_MISSING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": [\"dummy_key\"]}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdKeyNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"key\": 69}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIInsertCommand, kvdbInsertKeyCmdEmptyKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyOnly)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // get key and compare content
    ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(), "");
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyValue)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"{}\"}}",
                    DB_NAME,
                    KEY_A,
                    VAL_A)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // get key and compare content
    ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(),
              VAL_A);
}

TEST_F(kvdbAPIInsertCommand, ExecutionEmptyValue)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format(
            "{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"\"}}", DB_NAME, KEY_A)
            .c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    // get key and compare content
    ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(), "");
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
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& key : severalKeys)
    {
        json::Json params {
            fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, key).c_str()};
        const auto response = cmd(params);

        // check response
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 200);
        ASSERT_TRUE(response.message().has_value());
        ASSERT_STREQ(response.message().value().c_str(), "OK");

        // get key and compare content
        ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, key).value(),
                  "");
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
                                              "[^_`abcdefghijklmnopqrstuvwxyz{|}~"};
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
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
        ASSERT_EQ(response.error(), 200);
        ASSERT_TRUE(response.message().has_value());
        ASSERT_STREQ(response.message().value().c_str(), "OK");

        // get key and compare content
        ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(),
                  value);
    }
}

TEST_F(kvdbAPIInsertCommand, ExecutionWrongDBName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbInsertKeyCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"ANOTHER_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 "Key-value could not be written to the database");
}

// "kvdbListCmd" tests section

class kvdbAPIListCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_DIFFERENT_START = "NOT_TEST_DB";

    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
        kvdbManager->loadDB(DB_NAME, false);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIListCommand, kvdbListCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbListCmd(kvdbAPIListCommand::kvdbManager));
}

TEST_F(kvdbAPIListCommand, kvdbListCmdSingleDBLoaded)
{
    // add DB to loaded list
    kvdbManager->loadDB(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    const auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME);
}

TEST_F(kvdbAPIListCommand, kvdbListCmdNoneLoaded)
{
    // Deletes the only DB from the list
    kvdbAPIListCommand::kvdbManager->deleteDB(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    const auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    auto kvdbList = response.data().getArray();
    ASSERT_FALSE(kvdbList.has_value());
}

TEST_F(kvdbAPIListCommand, kvdbListCmdMultipleLoaded)
{
    // Adds another DB to the list
    kvdbAPIListCommand::kvdbManager->loadDB(DB_NAME);
    kvdbAPIListCommand::kvdbManager->loadDB(DB_NAME_2);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    const auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    auto kvdbList = response.data().getArray();
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
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::kvdbListCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params_with_name_not {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"NOT\"}}").c_str()};
    auto response = cmd(params_with_name_not);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

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
    ASSERT_EQ(response.error(), 200);

    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
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
    ASSERT_EQ(response.error(), 200);
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

    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
        kvdbManager = std::make_shared<KVDBManager>(DB_DIR);
        kvdbManager->CreateAndFillDBfromFile(DB_NAME);
        kvdbManager->writeKey(DB_NAME, KEY_A, VAL_A);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"dummy_key\": \"dummy_value\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummy_value\"]}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdKeyMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_MISSING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdKeyArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": [\"dummy_key\"]}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdKeyNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"key\": 69}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_NOT_A_STRING);
}

TEST_F(kvdbAPIRemoveCommand, kvdbRemoveKeyCmdEmptyKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), KVDB_KEY_EMPTY);
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecution)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    ASSERT_FALSE(
        kvdbAPIRemoveCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).has_value());
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecutionDoubleRemove)
{
    // GTEST_SKIP();
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(), "OK");

    response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Key \"{}\" could not be deleted", KEY_A).c_str());
}

TEST_F(kvdbAPIRemoveCommand, RemoveNonExistingDB)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"ANOTHER_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Key \"{}\" could not be deleted", KEY_A).c_str());
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithWrongKeyName)
{
    // TODO: there's an issue with KeyMayExist causing this test to fail
    // GTEST_SKIP();
    constexpr auto keyName = "ANOTHER_KEY_NAME";
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::kvdbRemoveKeyCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, keyName).c_str()};
    const auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_STREQ(response.message().value().c_str(),
                 fmt::format("Key \"{}\" could not be deleted", keyName).c_str());
}

// registerAllCmds section

TEST(kvdbAPICmdsTest, RegisterAllCmds)
{
    auto kvdbManager = std::make_shared<KVDBManager>(DB_DIR);

    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(api::kvdb::cmds::registerAllCmds(kvdbManager, apiReg));

    ASSERT_NO_THROW(apiReg->getCallback("create_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("create_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("delete_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("dump_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("get_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("insert_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("list_kvdb"));
    ASSERT_NO_THROW(apiReg->getCallback("remove_kvdb"));
}

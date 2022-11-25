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

// "createKvdbCmd" tests section

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
        kvdbManager->addDb(DB_NAME);
    }

    virtual void TearDown()
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }
};

TEST_F(kvdbAPICreateCommand, createKvdbCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNameMissing)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"not_name\": \"dummyString\"}"};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_EQ(response.message().value(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNameArrayNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": [\"dummyName\"]}"};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_EQ(response.message().value(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNameNumberNotString)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": 69}"};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_NOT_A_STRING);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdSimpleAddition)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {"{\"name\": \"\"}"};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdEmptyParams)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdDuplicatedDatabase)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(
        response.message().value(),
        fmt::format("Database \"{}\" could not be created", DB_NAME));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNameWithSpaces)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_WITH_SPACES).c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdWithFilling)
{
    // file creation
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
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   DB_NAME_2,
                                   FILE_PATH)
                           .c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check value
    auto handle = kvdbManager->getDB(DB_NAME_2);
    if (!handle)
    {
        kvdbManager->addDb(DB_NAME_2, false);
    }
    handle = kvdbManager->getDB(DB_NAME_2);
    ASSERT_TRUE(handle);
    ASSERT_EQ("valueA", handle->read("keyA"));
    ASSERT_EQ("valueB", handle->read("keyB"));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdWithWrongFilling)
{
    // file creation
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
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   DB_NAME_2,
                                   FILE_PATH)
                           .c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    // check value
    auto handle = kvdbManager->getDB(DB_NAME_2);
    if (!handle)
    {
        kvdbManager->addDb(DB_NAME_2, false);
    }
    handle = kvdbManager->getDB(DB_NAME_2);
    ASSERT_TRUE(handle);
    ASSERT_TRUE(handle->read("keyA").empty());
    ASSERT_TRUE(handle->read("keyB").empty());
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdSingleValueFile)
{
    // file creation
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
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   DB_NAME_2,
                                   FILE_PATH)
                           .c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check value
    auto handle = kvdbManager->getDB(DB_NAME_2);
    if (!handle)
    {
        kvdbManager->addDb(DB_NAME_2, false);
    }
    handle = kvdbManager->getDB(DB_NAME_2);
    ASSERT_TRUE(handle);
    ASSERT_TRUE(handle->hasKey("keyA"));
    ASSERT_TRUE(handle->hasKey("keyB"));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNonExistingFile)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::createKvdbCmd(kvdbAPICreateCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   DB_NAME_2,
                                   FILE_PATH)
                           .c_str()};
    auto response = cmd(params);

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

// "deleteKvdbCmd" tests section ----------------------------------------------------------------------------------------

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
        kvdbManager->addDb(DB_NAME);
    }

    size_t getNumberOfKVDBLoaded() { return kvdbManager->getAvailableKVDBs().size(); }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIDeleteCommand, deleteKvdbCmdSimpleLoaded)
{
    // add DB name with spaces
    kvdbAPIDeleteCommand::kvdbManager->addDb(DB_NAME_WITH_SPACES);

    // delete first DB
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::deleteKvdbCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 1);

    // delete DB named with spaces
    json::Json params_with_spaces {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"{}\"}}", DB_NAME_WITH_SPACES)
            .c_str()};
    response = cmd(params_with_spaces);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // trying to delete again already deleted DB
    response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST_F(kvdbAPIDeleteCommand, deleteKvdbCmdDoesntExistLoaded)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::deleteKvdbCmd(kvdbAPIDeleteCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"mustBeLoaded\": true, \"name\": \"{}\"}}", DB_NAME_NOT_AVAILABLE)
            .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getNumberOfKVDBLoaded(), 1);
}

// "dumpKvdbCmd" tests section

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
        kvdbManager->addDb(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIDumpCommand, dumpKvdbCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::dumpKvdbCmd(kvdbAPIDumpCommand::kvdbManager));
}

TEST_F(kvdbAPIDumpCommand, dumpKvdbCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::dumpKvdbCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"\"}}").c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIDumpCommand, dumpKvdbCmdNoParameters)
{
    // delete first DB
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::dumpKvdbCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIDumpCommand, dumpKvdbCmdSimpleExecution)
{
    // create file with content
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
    kvdbAPIDumpCommand::kvdbManager->CreateAndFillKVDBfromFile(DB_NAME_2, FILE_PATH);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::dumpKvdbCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check content
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(0).getString("/value").value(), "ValA");
    ASSERT_EQ(kvdbList.value().at(1).getString("/value").value(), "ValB");
    ASSERT_EQ(kvdbList.value().at(0).getString("/key").value(), "keyA");
    ASSERT_EQ(kvdbList.value().at(1).getString("/key").value(), "keyB");
}

TEST_F(kvdbAPIDumpCommand, dumpKvdbCmdSimpleEmpty)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::dumpKvdbCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    auto dataArray = response.data().getArray();
    ASSERT_FALSE(dataArray.has_value());
}

TEST_F(kvdbAPIDumpCommand, dumpKvdbCmdKVDBOnlyKeys)
{
    // create file with content
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
    kvdbAPIDumpCommand::kvdbManager->CreateAndFillKVDBfromFile(DB_NAME_2, FILE_PATH);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::dumpKvdbCmd(kvdbAPIDumpCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check content
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(0).getString("/key").value(), "keyA");
    ASSERT_EQ(kvdbList.value().at(1).getString("/key").value(), "keyB");
}

// "getKvdbCmd" tests section

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
        kvdbManager->CreateAndFillKVDBfromFile(DB_NAME);
        kvdbManager->writeKey(DB_NAME, KEY_A, VAL_A);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIGetCommand, getKvdbCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::getKvdbCmd(kvdbAPIGetCommand::kvdbManager));
}

TEST_F(kvdbAPIGetCommand, SimpleExecutionKeyOnly)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::getKvdbCmd(kvdbAPIGetCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // compare content
    auto data = response.data().getString("/value");
    ASSERT_TRUE(data.has_value());
    ASSERT_EQ(data.value(), VAL_A);
}

// "insertKvdbCmd" tests section

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
        kvdbManager->CreateAndFillKVDBfromFile(DB_NAME);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIInsertCommand, kvdbAPIInsertCommand)
{
    ASSERT_NO_THROW(api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyOnly)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // get key and compare content
    ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(), "");
}

TEST_F(kvdbAPIInsertCommand, SimpleExecutionKeyValue)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"{}\"}}",
                    DB_NAME,
                    KEY_A,
                    VAL_A)
            .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // get key and compare content
    ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(),
              VAL_A);
}

TEST_F(kvdbAPIInsertCommand, ExecutionNoKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "Parameter \"key\" is missing");
}

TEST_F(kvdbAPIInsertCommand, ExecutionEmptyKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "Parameter \"key\" is empty");
}

TEST_F(kvdbAPIInsertCommand, ExecutionNoName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"\"}}").c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIInsertCommand, ExecutionEmptyValue)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format(
            "{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"\"}}", DB_NAME, KEY_A)
            .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

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
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& key : severalKeys)
    {
        json::Json params {
            fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, key).c_str()};
        auto response = cmd(params);
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 200);

        // check response
        ASSERT_TRUE(response.message().has_value());
        ASSERT_EQ(response.message().value(), "OK");

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
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    for (const auto& value : severalValues)
    {
        json::Json params {
            fmt::format("{{\"name\": \"{}\", \"key\": \"{}\", \"value\": \"{}\"}}",
                        DB_NAME,
                        KEY_A,
                        value)
                .c_str()};
        auto response = cmd(params);
        ASSERT_TRUE(response.isValid());
        ASSERT_EQ(response.error(), 200);

        // check response
        ASSERT_TRUE(response.message().has_value());
        ASSERT_EQ(response.message().value(), "OK");

        // get key and compare content
        ASSERT_EQ(kvdbAPIInsertCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(),
                  value);
    }
}

TEST_F(kvdbAPIInsertCommand, ExecutionWrongDBName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::insertKvdbCmd(kvdbAPIInsertCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"ANOTHER_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(),
              "Key-value could not be written to the database");
}

// "listKvdbCmd" tests section

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
        kvdbManager->addDb(DB_NAME, false);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIListCommand, listKvdbCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::listKvdbCmd(kvdbAPIListCommand::kvdbManager));
}

TEST_F(kvdbAPIListCommand, listKvdbCmdSingleDBLoaded)
{
    // add DB to loaded list
    kvdbManager->addDb(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME);
}

TEST_F(kvdbAPIListCommand, listKvdbCmdNoneLoaded)
{
    // Deletes the only DB from the list
    kvdbAPIListCommand::kvdbManager->deleteDB(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    auto kvdbList = response.data().getArray();
    ASSERT_FALSE(kvdbList.has_value());
}

TEST_F(kvdbAPIListCommand, listKvdbCmdMultipleLoaded)
{
    // Adds another DB to the list
    kvdbAPIListCommand::kvdbManager->addDb(DB_NAME);
    kvdbAPIListCommand::kvdbManager->addDb(DB_NAME_2);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd(kvdbAPIListCommand::kvdbManager));
    json::Json params {fmt::format("{{\"mustBeLoaded\": true}}").c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(), 2);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(), DB_NAME_2);
    ASSERT_EQ(kvdbList.value().at(1).getString().value(), DB_NAME);
}

TEST_F(kvdbAPIListCommand, listKvdbCmdWithFilteringLoaded)
{
    // Adds DB to the list
    kvdbAPIListCommand::kvdbManager->addDb(DB_NAME);
    // add a db wicha name starts different than the others
    kvdbAPIListCommand::kvdbManager->addDb(DB_NAME_DIFFERENT_START);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd(kvdbAPIListCommand::kvdbManager));
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

// "removeKvdbCmd" tests section

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
        kvdbManager->CreateAndFillKVDBfromFile(DB_NAME);
        kvdbManager->writeKey(DB_NAME, KEY_A, VAL_A);
    }

    virtual void TearDown() {}
};

TEST_F(kvdbAPIRemoveCommand, removeKvdbCmd)
{
    ASSERT_NO_THROW(api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecution)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    ASSERT_EQ(kvdbAPIRemoveCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(), "");
}

TEST_F(kvdbAPIRemoveCommand, SimpleExecutionDoubleRemove)
{
    GTEST_SKIP();
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // when doing this the deleted value gets updated
    // ASSERT_EQ(kvdbAPIRemoveCommand::kvdbManager->getKeyValue(DB_NAME, KEY_A).value(), "");

    response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(),
              fmt::format("Key \"{}\" could not be deleted", KEY_A));
}

TEST_F(kvdbAPIRemoveCommand, RemoveNonExistingDB)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"ANOTHER_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(),
              fmt::format("Key \"{}\" could not be deleted", KEY_A));
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithEmptyKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "Parameter \"key\" is empty");
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithNonExistingKey)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "Parameter \"key\" is missing");
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithWrongKeyName)
{
    // TODO: there's an issue with KeyMayExist causing this test to fail
    GTEST_SKIP();
    constexpr auto keyName = "ANOTHER_KEY_NAME";
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"key\": \"{}\"}}", DB_NAME, keyName).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(),
              fmt::format("Key \"{}\", could not be deleted", keyName));
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithEmptyKVDBName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {fmt::format("{{\"name\": \"\", \"key\": \"{}\"}}", KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_EMPTY);
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithNonExistingKVDBName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    auto response = cmd(json::Json {});
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), KVDB_NAME_MISSING);
}

TEST_F(kvdbAPIRemoveCommand, RemoveWithWrongKVDBName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(
        cmd = api::kvdb::cmds::removeKvdbCmd(kvdbAPIRemoveCommand::kvdbManager));
    json::Json params {
        fmt::format("{{\"name\": \"WRONG_DB_NAME\", \"key\": \"{}\"}}", KEY_A).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(),
              fmt::format("Key \"{}\" could not be deleted", KEY_A));
}

// registerAllCmds section

TEST(kvdbAPICmdsTest, RegisterAllCmds)
{
    auto kvdbManager = std::make_shared<KVDBManager>(DB_DIR);

    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(api::kvdb::cmds::registerAllCmds(kvdbManager, apiReg));

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = apiReg->getCallback("create_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("create_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("delete_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("dump_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("get_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("insert_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("list_kvdb"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("remove_kvdb"));
}

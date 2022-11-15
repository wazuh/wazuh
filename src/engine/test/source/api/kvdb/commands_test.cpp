#include <api/kvdb/commands.hpp>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

// TODO: "createKvdbCmd" tests section (To avoid conflicts) ------------------------------
class kvdbAPICreateCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_NAME_2 = "TEST_DB_2";
    static constexpr auto DB_NAME_3 = "TEST_DB_3";
    static constexpr auto DB_NAME_WITH_SPACES = "TEST_DB SEPARATE NAME";
    static constexpr auto DB_DIR = "/tmp/";
    static constexpr auto FILE_PATH = "/tmp/file.csv";

    bool init = []()
    {
        static bool once = false;
        if (!once)
        {
            once = true;
            KVDBManager::init(kvdbAPICreateCommand::DB_DIR);
        }

        return true;
    }();
    KVDBManager& kvdbManager = KVDBManager::get();

    virtual void SetUp()
    {
        if (!kvdbManager.getDB(DB_NAME))
        {
            kvdbManager.addDb(DB_NAME);
        }
    }

    void deleteDB(const std::string& db_name) { kvdbManager.deleteDB(db_name); }

    virtual void TearDown()
    {
        if (!kvdbManager.getDB(DB_NAME))
        {
            kvdbManager.deleteDB(DB_NAME);
        }

        if (!kvdbManager.getDB(DB_NAME_2))
        {
            kvdbManager.deleteDB(DB_NAME_2);
        }

        if (!kvdbManager.getDB(DB_NAME_WITH_SPACES))
        {
            kvdbManager.deleteDB(DB_NAME_WITH_SPACES);
        }

        if (std::filesystem::exists(kvdbAPICreateCommand::FILE_PATH))
        {
            std::filesystem::remove(kvdbAPICreateCommand::FILE_PATH);
        }
    }
};

TEST_F(kvdbAPICreateCommand, createKvdbCmdSimpleAddition)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", kvdbAPICreateCommand::DB_NAME_2).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNamesInArray)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": [\"{}\",\"{}\"]}}",
                                   kvdbAPICreateCommand::DB_NAME_2,
                                   kvdbAPICreateCommand::DB_NAME_3)
                           .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdEmptyName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"\"}}").c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdEmptyParams)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdRepeatedName)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", kvdbAPICreateCommand::DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(
        response.message().value(),
        fmt::format("DB with name [{}] already exists.", kvdbAPICreateCommand::DB_NAME));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNameWithSpaces)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", kvdbAPICreateCommand::DB_NAME_WITH_SPACES)
            .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdWithFilling)
{
    // file creation
    if (!std::filesystem::exists(kvdbAPICreateCommand::FILE_PATH))
    {
        std::ofstream exampleFile(kvdbAPICreateCommand::FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA:valueA\n";
            exampleFile << "keyB:valueB\n";
            exampleFile.close();
        }
    }

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   kvdbAPICreateCommand::DB_NAME_2,
                                   kvdbAPICreateCommand::FILE_PATH)
                           .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check value
    auto handle =
        kvdbAPICreateCommand::kvdbManager.get().getDB(kvdbAPICreateCommand::DB_NAME_2);
    ASSERT_EQ("valueA", handle->read("keyA"));
    ASSERT_EQ("valueB", handle->read("keyB"));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdWithWrongFilling)
{
    // file creation
    if (!std::filesystem::exists(kvdbAPICreateCommand::FILE_PATH))
    {
        std::ofstream exampleFile(kvdbAPICreateCommand::FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA-valueA\n";
            exampleFile << "keyB,valueB\n";
            exampleFile.close();
        }
    }

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   kvdbAPICreateCommand::DB_NAME_2,
                                   kvdbAPICreateCommand::FILE_PATH)
                           .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdSingleValueFile)
{
    // file creation
    if (!std::filesystem::exists(kvdbAPICreateCommand::FILE_PATH))
    {
        std::ofstream exampleFile(kvdbAPICreateCommand::FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << "keyA\n";
            exampleFile << "keyB\n";
            exampleFile.close();
        }
    }

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   kvdbAPICreateCommand::DB_NAME_2,
                                   kvdbAPICreateCommand::FILE_PATH)
                           .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check value
    auto handle =
        kvdbAPICreateCommand::kvdbManager.get().getDB(kvdbAPICreateCommand::DB_NAME_2);
    ASSERT_TRUE(handle->hasKey("keyA"));
    ASSERT_TRUE(handle->hasKey("keyB"));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNonExistingFile)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"{}\", \"path\":\"{}\"}}",
                                   kvdbAPICreateCommand::DB_NAME_2,
                                   kvdbAPICreateCommand::FILE_PATH)
                           .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

// TODO: "deleteKvdbCmd" tests section (To avoid conflicts) ------------------------------
class kvdbAPIDeleteCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_NAME_WITH_SPACES = "TEST_DB NAME";
    static constexpr auto DB_NAME_NOT_AVAILABLE = "TEST_DB_NOT_AVAILABLE";
    static constexpr auto DB_DIR = "/tmp/";

    bool init = []()
    {
        static bool once = false;
        if (!once)
        {
            once = true;
            KVDBManager::init(kvdbAPIDeleteCommand::DB_DIR);
        }

        return true;
    }();
    KVDBManager& kvdbManager = KVDBManager::get();

    virtual void SetUp()
    {
        if (!kvdbManager.getDB(DB_NAME))
        {
            kvdbManager.addDb(DB_NAME);
        }
    }

    size_t getQttyOfKVDB() { return kvdbManager.getAvailableKVDBs().size(); }

    void AddSpaceNameDB()
    {
        if (!kvdbManager.getDB(DB_NAME_WITH_SPACES))
        {
            kvdbManager.addDb(DB_NAME_WITH_SPACES);
        }
    }

    virtual void TearDown()
    {
        if (!kvdbManager.getDB(DB_NAME))
        {
            kvdbManager.deleteDB(DB_NAME);
        }

        if (!kvdbManager.getDB(DB_NAME_WITH_SPACES))
        {
            kvdbManager.deleteDB(DB_NAME_WITH_SPACES);
        }
    }
};

TEST_F(kvdbAPIDeleteCommand, deleteKvdbCmdSimple)
{
    // add DB name with spaces
    kvdbAPIDeleteCommand::AddSpaceNameDB();

    // delete first DB
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::deleteKvdbCmd());
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", kvdbAPIDeleteCommand::DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getQttyOfKVDB(), 1);

    // delete DB named with spaces
    json::Json params_with_spaces {
        fmt::format("{{\"name\": \"{}\"}}", kvdbAPIDeleteCommand::DB_NAME_WITH_SPACES)
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

TEST_F(kvdbAPIDeleteCommand, deleteKvdbCmdDoesntExist)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::deleteKvdbCmd());
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", kvdbAPIDeleteCommand::DB_NAME_NOT_AVAILABLE)
            .c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check remaining available DBs
    ASSERT_EQ(kvdbAPIDeleteCommand::getQttyOfKVDB(), 1);
}

// TODO: "dumpKvdbCmd" tests section (To avoid conflicts) --------------------------------

// TODO: "getKvdbCmd" tests section (To avoid conflicts) ---------------------------------

// TODO: "insertKvdbCmd" tests section (To avoid conflicts) ------------------------------

class kvdbAPIInsertCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_DIR = "/tmp/";

    bool init = []()
    {
        static bool once = false;
        if (!once)
        {
            once = true;
            KVDBManager::init(kvdbAPIInsertCommand::DB_DIR);
        }

        return true;
    }();

    KVDBManager& kvdbManager = KVDBManager::get();

    virtual void SetUp()
    {
        if (!kvdbManager.getDB(DB_NAME))
        {
            kvdbManager.addDb(DB_NAME);
        }
    }

    virtual void TearDown() { kvdbManager.deleteDB(DB_NAME); }
};

TEST_F(kvdbAPIInsertCommand, test)
{
    api::CommandFn cmd {};
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::insertKvdbCmd());
}

// TODO: "listKvdbCmd" tests section (To avoid conflicts) --------------------------------

class kvdbAPIListCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_NAME_2 = "TEST_DB_2";
    static constexpr auto DB_NAME_DIFFERENT_START = "NOT_TEST_DB";
    static constexpr auto DB_DIR = "/tmp/";

    bool init = []()
    {
        static bool once = false;
        if (!once)
        {
            once = true;
            KVDBManager::init(kvdbAPIListCommand::DB_DIR);
        }

        return true;
    }();
    KVDBManager& kvdbManager = KVDBManager::get();

    virtual void SetUp()
    {
        if (!kvdbManager.getDB(DB_NAME))
        {
            kvdbManager.addDb(DB_NAME);
        }
    }

    void deleteDB(const std::string& db_name) { kvdbManager.deleteDB(db_name); }

    virtual void TearDown() { kvdbManager.deleteDB(DB_NAME); }
};

TEST_F(kvdbAPIListCommand, listKvdbCmdSingleDB)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd());
    json::Json params {};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    //check response
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(),1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(),DB_NAME);
}

TEST_F(kvdbAPIListCommand, listKvdbCmdNone)
{
    // Deletes the only DB from the list
    kvdbAPIListCommand::deleteDB(DB_NAME);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd());
    json::Json params {};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    //check response
    auto val = response.data().prettyStr();
    auto kvdbList = response.data().getArray();
    ASSERT_FALSE(kvdbList.has_value());
}

TEST_F(kvdbAPIListCommand, listKvdbCmdMultiple)
{
    // Adds another DB to the list
    kvdbAPIListCommand::kvdbManager.addDb(DB_NAME_2);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd());
    json::Json params {};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    //check response
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(),2);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(),DB_NAME_2);
    ASSERT_EQ(kvdbList.value().at(1).getString().value(),DB_NAME);

    //leave DBs as it was at the beggining
    kvdbAPIListCommand::deleteDB(DB_NAME_2);
}

TEST_F(kvdbAPIListCommand, listKvdbCmdWithFiltering)
{
    // add a db wicha name starts different than the others
    kvdbAPIListCommand::kvdbManager.addDb(DB_NAME_DIFFERENT_START);
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd());
    json::Json params_with_name_not {
    fmt::format("{{\"name\": \"NOT\"}}").c_str()};
    auto response = cmd(params_with_name_not);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    //check response with different name filtered
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(),1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(),DB_NAME_DIFFERENT_START);

    // same procces filtering with previous name start
    json::Json params_with_name_test {
    fmt::format("{{\"name\": \"TEST_\"}}").c_str()};
    response = cmd(params_with_name_test);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(),1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(),DB_NAME);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    json::Json params_with_empty_name {
    fmt::format("{{\"name\": \"\"}}").c_str()};
    response = cmd(params_with_empty_name);
    kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(),2);
    ASSERT_EQ(kvdbList.value().at(1).getString().value(),DB_NAME);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(),DB_NAME_DIFFERENT_START);

    // checks without filtering
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
    json::Json params_with_wrong_name {
    fmt::format("{{\"name\": \"wrong_match\"}}").c_str()};
    response = cmd(params_with_wrong_name);
    kvdbList = response.data().getArray();
    ASSERT_FALSE(kvdbList.has_value());
}

// TODO: "removeKvdbCmd" tests section (To avoid conflicts) ------------------------------

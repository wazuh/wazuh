#include <api/kvdb/commands.hpp>
#include <gtest/gtest.h>

// TODO: "createKvdbCmd" tests section (To avoid conflicts) ------------------------------
class kvdbAPICreateCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_NAME_2 = "TEST_DB_2";
    static constexpr auto DB_NAME_3 = "TEST_DB_3";
    static constexpr auto DB_DIR = "/tmp/";

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

    virtual void TearDown() { kvdbManager.deleteDB(DB_NAME); }
};

TEST_F(kvdbAPICreateCommand, createKvdbCmdSimpleAddition)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME_2).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(), "OK");

    // leave DBs as it was at the beggining
    kvdbAPICreateCommand::deleteDB(DB_NAME_2);
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNamesInArray)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {
        fmt::format("{{\"name\": [\"{}\",\"{}\"]}}", DB_NAME_2, DB_NAME_3).c_str()};
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
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);

    // check response
    ASSERT_TRUE(response.message().has_value());
    ASSERT_EQ(response.message().value(),
              fmt::format("DB with name [{}] already exists.", DB_NAME));
}

TEST_F(kvdbAPICreateCommand, createKvdbCmdNameWithSpaces)
{
    // TODO: Should we allow db names with spaces in between? rocksdb doesn't complain
    // about it -> /tmp/'TEST_DB ANOTHER_NAME'
    GTEST_SKIP();
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::createKvdbCmd());
    json::Json params {fmt::format("{{\"name\": \"{} ANOTHER_NAME\"}}", DB_NAME).c_str()};
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

// TODO: "deleteKvdbCmd" tests section (To avoid conflicts) ------------------------------

// TODO: "dumpKvdbCmd" tests section (To avoid conflicts) --------------------------------

// TODO: "getKvdbCmd" tests section (To avoid conflicts) ---------------------------------

// TODO: "insertKvdbCmd" tests section (To avoid conflicts) ------------------------------

// TODO: "listKvdbCmd" tests section (To avoid conflicts) --------------------------------

class kvdbAPIListCommand : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_NAME_2 = "TEST_DB_2";
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
    ASSERT_NO_THROW(cmd(params));
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
    ASSERT_NO_THROW(cmd(params));
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
    ASSERT_NO_THROW(cmd(params));
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

TEST_F(kvdbAPIListCommand, listKvdbCmdWithParams)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::listKvdbCmd());
    json::Json params {
    fmt::format("{{\"name\": \"nameVal\", \"format\": \"json\"}}").c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);

    //check response
    auto kvdbList = response.data().getArray();
    ASSERT_TRUE(kvdbList.has_value());
    ASSERT_EQ(kvdbList.value().size(),1);
    ASSERT_EQ(kvdbList.value().at(0).getString().value(),DB_NAME);
}

// TODO: "removeKvdbCmd" tests section (To avoid conflicts) ------------------------------

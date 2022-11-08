#include <api/kvdb/commands.hpp>
#include <gtest/gtest.h>

// TODO: why this namespace?
namespace
{

// TODO: Move the listKvdbCmd tests to its section
class commandKVDBTest : public ::testing::Test
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
            KVDBManager::init(commandKVDBTest::DB_DIR);
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

TEST_F(commandKVDBTest, listKvdbCmdSingleDB)
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

TEST_F(commandKVDBTest, listKvdbCmdNone)
{
    // Deletes the only DB from the list
    commandKVDBTest::kvdbManager.deleteDB(DB_NAME);

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

TEST_F(commandKVDBTest, listKvdbCmdMultiple)
{
    // Adds another DB to the list
    commandKVDBTest::kvdbManager.addDb(DB_NAME_2);

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
}

}

// TODO: "createKvdbCmd" tests section (To avoid conflicts) ------------------------------

// TODO: "deleteKvdbCmd" tests section (To avoid conflicts) ------------------------------

// TODO: "dumpKvdbCmd" tests section (To avoid conflicts) --------------------------------

// TODO: "getKvdbCmd" tests section (To avoid conflicts) ---------------------------------

// TODO: "insertKvdbCmd" tests section (To avoid conflicts) ------------------------------

// TODO: "listKvdbCmd" tests section (To avoid conflicts) --------------------------------

// TODO: "removeKvdbCmd" tests section (To avoid conflicts) ------------------------------

#include <api/kvdb/commands.hpp>
#include <gtest/gtest.h>

namespace
{

class commandKVDBTest : public ::testing::Test
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

TEST_F(commandKVDBTest, lisKvdbCmd)
{
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = api::kvdb::cmds::lisKvdbCmd());
    json::Json params {};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

}

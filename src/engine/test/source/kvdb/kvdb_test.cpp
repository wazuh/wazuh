#include <filesystem>

#include "gtest/gtest.h"
#include <kvdb/kvdbManager.hpp>

//TODO: can we move this utility functions to headers accesible to tests and benchmark?
static std::string getRandomString(int len, bool includeSymbols = false) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    static const char symbols[] =
        "-_'\\/. *!\"#$%&()+[]{},;";

    std::string tmp_s;
    tmp_s.reserve(len);

    std::string dict = alphanum;
    if(includeSymbols)
    {
        dict += symbols;
    }

    for (int i = 0; i < len; ++i) {
        tmp_s += dict[rand() % dict.size()];
    }
    return tmp_s;
}

TEST(kvdbTests, create_delete_kvd_file)
{
    KVDBManager& kvdbManager = KVDBManager::getInstance();
    kvdbManager.createDB("TEST"); // TODO Move this to Setup()
    KVDB& kvdb1 = kvdbManager.getDB("TEST");
    ASSERT_EQ(kvdb1.getName(), "TEST");
    ASSERT_EQ(kvdb1.getState(), KVDB::State::Open);
    kvdbManager.DeleteDB("TEST"); // TODO Move this to TearDown()

    KVDB& invalid_kvdb = kvdbManager.getDB("TEST_INVALID");
    ASSERT_EQ(invalid_kvdb.getState(), KVDB::State::Invalid);
    ASSERT_EQ(invalid_kvdb.getName(), "Invalid");

}

TEST(kvdbTests, create_delete_columns)
{
    KVDBManager& kvdbManager = KVDBManager::getInstance();
    KVDB& kvdb = kvdbManager.getDB("TEST");
    bool ret = kvdb.createColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = kvdb.deleteColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = kvdb.deleteColumn("IP_BLACKLIST");
    ASSERT_TRUE(!ret);
}

TEST(kvdbTests, read_write_column_family)
{
    std::string valIn, valOut, valWithoutCopy;
    KVDBManager& kvdbManager = KVDBManager::getInstance();
    KVDB& kvdb = kvdbManager.getDB("TEST");
    bool ret = kvdb.createColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = kvdb.deleteColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valIn = "192.168.10.2";
    ret = kvdb.write("IP_BLACKLIST", "someKey", valIn);
    ASSERT_TRUE(ret);
    valIn = "127.0.0.1";
    ret = kvdb.write("IP_BLACKLIST", "someKey", valIn);
    ASSERT_TRUE(ret);
    valOut = kvdb.read("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(ret);
    ASSERT_EQ(valOut,"127.0.0.1");

    ret = kvdb.createColumn("IP_GEO_TAGGING");
    ASSERT_TRUE(ret);
    valIn = "31.4201S,64.1888W";
    ret = kvdb.write("IP_GEO_TAGGING", "position", valIn);
    ASSERT_TRUE(ret);
    ret = kvdb.readPinned("position", valWithoutCopy, "IP_GEO_TAGGING");
    ASSERT_TRUE(ret);
    ASSERT_EQ(valWithoutCopy,"31.4201S,64.1888W");

    ret = kvdb.deleteKey("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(ret);
    valOut = kvdb.read("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(!ret);
}

TEST(kvdbTests, transactions_success)
{
    std::string value;
    std::vector<std::pair<std::string,std::string>> vPairs = {{"key1","value1"},
    {"key2","value2"}, {"key3","value3"}, {"key4","value4"}, {"key5","value5"}};

    KVDBManager& kvdbManager = KVDBManager::getInstance();
    KVDB& kvdb = kvdbManager.getDB("TEST");

    bool ret = kvdb.createColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    value = "192.168.10.2";
    ret = kvdb.write("IP_BLACKLIST", "someKey", value);
    ASSERT_TRUE(ret);
    ret = kvdb.writeToTransaction(vPairs, "IP_BLACKLIST");
    ASSERT_TRUE(ret);

    value = kvdb.read("IP_BLACKLIST", "key1");
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value1");
    value = kvdb.read("IP_BLACKLIST", "key2");
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value2");
    value = kvdb.read("IP_BLACKLIST", "key3");
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value3");
    value = kvdb.read("IP_BLACKLIST", "key4");
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value4");
    value = kvdb.read("IP_BLACKLIST", "key5");
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value5");
}

TEST(kvdbTests, clean_column_family)
{
    std::string valueOut, valueIn;
    KVDBManager& kvdbManager = KVDBManager::getInstance();
    KVDB& kvdb = kvdbManager.getDB("TEST");

    bool ret = kvdb.createColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valueIn = "127.0.0.1";
    ret = kvdb.write("IP_BLACKLIST", "someKey", valueIn);
    ASSERT_TRUE(ret);
    valueOut = kvdb.read("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(ret);
    ASSERT_EQ(valueOut,"127.0.0.1");
    ret =  kvdb.cleanColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valueIn = "255.255.255.0";
    valueOut = kvdb.read("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(!ret);
    ret = kvdb.write("IP_BLACKLIST", "AnotherKey", valueIn);
    ASSERT_TRUE(ret);
    valueOut = kvdb.read("IP_BLACKLIST", "AnotherKey");
    ASSERT_TRUE(ret);
    ASSERT_EQ(valueOut,"255.255.255.0");
}

TEST(kvdbTests, value_key_length)
{
    std::string valInput, valOutput;
    KVDBManager& kvdbManager = KVDBManager::getInstance();
    KVDB& kvdb = kvdbManager.getDB("TEST");

    bool ret = kvdb.createColumn("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valInput = getRandomString(128,true);
    ret = kvdb.write("IP_BLACKLIST", "anyKey", valInput);
    ASSERT_TRUE(ret);
    valOutput = kvdb.read("IP_BLACKLIST", "anyKey");
    ASSERT_TRUE(ret);

    valInput = getRandomString(512,true);
    ret = kvdb.write("IP_BLACKLIST", "anyKey", valInput);
    ASSERT_TRUE(ret);
    valOutput = kvdb.read("IP_BLACKLIST", "anyKey");
    ASSERT_TRUE(ret);

    valInput = getRandomString(1024,true);
    ret = kvdb.write("IP_BLACKLIST", "anyKey", valInput);
    ASSERT_TRUE(ret);
    valOutput = kvdb.read("IP_BLACKLIST", "anyKey");
    ASSERT_EQ(valOutput,valInput);
    ASSERT_TRUE(ret);
}

TEST(kvdbTests, concurrent_write)
{
    // TODO: how to test a concurrent acces to Rocksdb, it must
    // * use kvdb methods
    //   * not possible to use transactions without commit
    // * block access to a DB while being used
    // * allow concurrent access to different DBs within RockdDB
}

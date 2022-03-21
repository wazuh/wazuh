#include <filesystem>

#include "gtest/gtest.h"
#include <kvdb/kvdb.hpp>

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
    DestroyKVDB();
    bool ret = CreateKVDB();
    ASSERT_TRUE(ret);
    ret = DestroyKVDB();
    ASSERT_TRUE(ret);
    ret = CreateKVDB();
    ASSERT_TRUE(ret);
    ret = std::filesystem::exists("/tmp/kvDB_wazuh_engine");
    ASSERT_TRUE(ret);
    ret = std::filesystem::is_directory("/tmp/kvDB_wazuh_engine");
    ASSERT_TRUE(ret);
    ret = DestroyKVDB();
    ASSERT_TRUE(ret);
    ret = DestroyKVDB();
    ASSERT_TRUE(!ret);
}

TEST(kvdbTests, column_family_creation_deletion)
{
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = CreateColumnFamily("IP_GEO_TAGGING");
    ASSERT_TRUE(ret);
    ret = DropColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = CreateColumnFamily("");
    ASSERT_TRUE(!ret);
    ret = DropColumnFamily("NOT_AVAILABLE");
    ASSERT_TRUE(!ret);
}

TEST(kvdbTests, read_write_column_family)
{
    std::string valIn, valOut, valWithoutCopy;
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    valIn = "192.168.10.2";
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", valIn);
    ASSERT_TRUE(ret);
    valIn = "127.0.0.1";
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", valIn);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", valOut);
    ASSERT_TRUE(ret);
    ASSERT_EQ(valOut,"127.0.0.1");

    ret = CreateColumnFamily("IP_GEO_TAGGING");
    ASSERT_TRUE(ret);
    valIn = "31.4201S,64.1888W";
    ret = WriteToColumnFamily("IP_GEO_TAGGING", "position", valIn);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamilyWithoutValueCopy("IP_GEO_TAGGING", "position", valWithoutCopy);
    ASSERT_TRUE(ret);
    ASSERT_EQ(valWithoutCopy,"31.4201S,64.1888W");

    ret = DeleteKeyInColumnFamily("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", valOut);
    ASSERT_TRUE(!ret);
    ret = DropColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
}

TEST(kvdbTests, transactions_success)
{
    std::string value;
    std::vector<std::pair<std::string,std::string>> vPairs = {{"key1","value1"},
    {"key2","value2"}, {"key3","value3"}, {"key4","value4"}, {"key5","value5"}};

    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    value = "192.168.10.2";
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", value);
    ASSERT_TRUE(ret);
    ret = WriteToColumnFamilyTransaction("IP_BLACKLIST", vPairs);
    ASSERT_TRUE(ret);

    ret = ReadToColumnFamily("IP_BLACKLIST", "key1", value);
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value1");
    ret = ReadToColumnFamily("IP_BLACKLIST", "key2", value);
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value2");
    ret = ReadToColumnFamily("IP_BLACKLIST", "key3", value);
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value3");
    ret = ReadToColumnFamily("IP_BLACKLIST", "key4", value);
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value4");
    ret = ReadToColumnFamily("IP_BLACKLIST", "key5", value);
    ASSERT_TRUE(ret);
    ASSERT_EQ(value,"value5");
}

TEST(kvdbTests, clean_column_family)
{
    std::string valueOut, valueIn;
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valueIn = "127.0.0.1";
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", valueIn);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", valueOut);
    ASSERT_TRUE(ret);
    ASSERT_EQ(valueOut,"127.0.0.1");
    ret = CleanColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valueIn = "255.255.255.0";
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", valueIn);
    ASSERT_TRUE(!ret);
    ret = WriteToColumnFamily("IP_BLACKLIST", "AnotherKey", valueIn);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "AnotherKey", valueOut);
    ASSERT_TRUE(ret);
    ASSERT_EQ(valueOut,"255.255.255.0");
}

TEST(kvdbTests, value_key_length)
{
    std::string valInput, valOutput;
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);

    valInput = getRandomString(128,true);
    ret = WriteToColumnFamily("IP_BLACKLIST", "anyKey", valInput);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "anyKey", valOutput);
    ASSERT_TRUE(ret);

    valInput = getRandomString(512,true);
    ret = WriteToColumnFamily("IP_BLACKLIST", "anyKey", valInput);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "anyKey", valOutput);
    ASSERT_TRUE(ret);

    valInput = getRandomString(1024,true);
    ret = WriteToColumnFamily("IP_BLACKLIST", "anyKey", valInput);
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "anyKey", valOutput);
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

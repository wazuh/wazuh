#include "gtest/gtest.h"
#include <kvdb/kvdb.hpp>

TEST(kvdbTests, create_delete_kvd_file)
{
    DestroyKVDB(); //TODO: find another way of deleting DB in kDPath
    bool ret = CreateKVDB();
    ASSERT_TRUE(ret);
    ret = DestroyKVDB();
    ASSERT_TRUE(ret);
    ret = CreateKVDB();
    ASSERT_TRUE(ret);
    //TODO: Check precence of file or directory in kDBPath
    //ASSERT_EQ(kDBPath,path_obtained);
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
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", "192.168.10.2");
    ASSERT_TRUE(ret);
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", "127.0.0.1");
    ASSERT_TRUE(ret);
    std::string val;
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", val);
    ASSERT_TRUE(ret);
    ASSERT_EQ(val,"127.0.0.1");
    ret = WriteToColumnFamily("IP_GEO_TAGGING", "position", "31.4201S,64.1888W");
    ASSERT_TRUE(ret);
    std::string valWithoutCopy;
    ret = ReadToColumnFamilyWithoutValueCopy("IP_GEO_TAGGING", "position", valWithoutCopy);
    ASSERT_TRUE(ret);
    ASSERT_EQ(valWithoutCopy,"31.4201S,64.1888W");
    ret = DeleteKeyInColumnFamily("IP_BLACKLIST", "someKey");
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", val);
    ASSERT_TRUE(!ret);
    ret = DropColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
}

TEST(kvdbTests, transactions_success)
{
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", "192.168.10.2");
    ASSERT_TRUE(ret);
    std::vector<std::pair<std::string,std::string>> vPairs = {{"key1","value1"},
        {"key2","value2"}, {"key3","value3"}, {"key4","value4"}, {"key5","value5"}};
    ret = WriteToColumnFamilyTransaction("IP_BLACKLIST", vPairs);
    ASSERT_TRUE(ret);
    std::string val;
    ret = ReadToColumnFamily("IP_BLACKLIST", "key2", val);
    ASSERT_TRUE(ret);
    ASSERT_EQ(val,"value2");
}

TEST(kvdbTests, clean_column_family)
{
    bool ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = WriteToColumnFamily("IP_BLACKLIST", "someKey", "127.0.0.1");
    ASSERT_TRUE(ret);
    std::string val;
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", val);
    ASSERT_TRUE(ret);
    ASSERT_EQ(val,"127.0.0.1");
    ret = CleanColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    val = std::string();
    ret = ReadToColumnFamily("IP_BLACKLIST", "someKey", val);
    ASSERT_TRUE(!ret);
    ret = WriteToColumnFamily("IP_BLACKLIST", "AnotherKey", "255.255.255.0");
    ASSERT_TRUE(ret);
    ret = ReadToColumnFamily("IP_BLACKLIST", "AnotherKey", val);
    ASSERT_TRUE(ret);
    ASSERT_EQ(val,"255.255.255.0");
}

#include "gtest/gtest.h"
#include <kvdb/kvdb.hpp>


TEST(kvdbTests, column_family_creation_deletion)
{
    bool ret = CreateKVDB();
    ASSERT_TRUE(ret);
    ret = CreateColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = DeleteColumnFamily("IP_BLACKLIST");
    ASSERT_TRUE(ret);
    ret = CreateColumnFamily("");
    ASSERT_TRUE(!ret);
    ret = DeleteColumnFamily("NOT_AVAILABLE");
    ASSERT_TRUE(!ret);
    ret = DestroyKVDB();
    ASSERT_TRUE(ret);
}

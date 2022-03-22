#include <filesystem>

#include "gtest/gtest.h"
#include <kvdb/kvdbManager.hpp>

TEST(kvdbTests, create_delete_kvd_file)
{
    KVDBManager& kvdbManager = KVDBManager::getInstance();

    KVDB& kvdb1 = kvdbManager.getDB("TEST");
    KVDB& kvdb2 = kvdbManager.getDB("TEST");
    KVDB& kvdb3 = kvdbManager.getDB("TESTA"); //TODO: KVDB Manager Error control?
    //kvdb1.write()...
}

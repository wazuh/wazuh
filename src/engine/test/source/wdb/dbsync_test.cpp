#include <wdb/dbsync.hpp>

#include <gtest/gtest.h>

TEST(wdb_dbsync, Init)
{
    ASSERT_TRUE(wazuhdb::dbsync::dbSync(nullptr));
}

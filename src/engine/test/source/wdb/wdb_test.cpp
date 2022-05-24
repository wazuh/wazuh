#include <wdb/wdb.hpp>

#include <gtest/gtest.h>

using namespace wazuhdb;

TEST(wdb_connector, init)
{
    ASSERT_THROW(WazuhDB("/tmp/wdb123"), std::runtime_error);
    ASSERT_THROW(WazuhDB(""), std::runtime_error);
    ASSERT_THROW(WazuhDB(), std::runtime_error);
}

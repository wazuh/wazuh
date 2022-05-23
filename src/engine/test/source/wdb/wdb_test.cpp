#include <wdb/wdb.hpp>

#include <gtest/gtest.h>


TEST(wdb_connector, init)
{
    ASSERT_THROW(WazuhDB("/tmp/wdb123"), std::runtime_error);
    ASSERT_THROW(WazuhDB(""), std::runtime_error);
    ASSERT_THROW(WazuhDB(), std::runtime_error);
}

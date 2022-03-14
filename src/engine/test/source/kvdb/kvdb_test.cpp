#include "gtest/gtest.h"

#include <kvdb/kvdb.hpp>


TEST(kvdbTests, execute_simple_example)
{
    fprintf(stderr, "\n\n---KVDB Test---\n");
    kvdb_simple_example();
}

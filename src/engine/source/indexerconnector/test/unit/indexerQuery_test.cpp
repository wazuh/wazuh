#include "indexerQuery_test.hpp"
#include <indexerQuery.hpp>

// Test bulkIndex method
TEST_F(IndexerQueryTest, BulkIndexWithId)
{
    auto buildedQuery = IndexerQuery::bulkIndex("test-index", "123", "");
    std::string expected = R"({"index":{"_index":"test-index","_id":"123"}})";
    EXPECT_EQ(buildedQuery, expected + "\n\n");
}

// Test bulkIndex method without ID
TEST_F(IndexerQueryTest, BulkIndexWithoutId)
{
    auto buildedQuery = IndexerQuery::bulkIndex("test-index", "", "");
    std::string expected = R"({"index":{"_index":"test-index"}})";
    EXPECT_EQ(buildedQuery, expected + "\n\n");
}

// Test deleteIndex method with ID
TEST_F(IndexerQueryTest, DeleteIndexWithId)
{
    auto buildedQuery = IndexerQuery::deleteIndex("test-index", "123");
    std::string expected = R"({"delete":{"_index":"test-index","_id":"123"}})";
    EXPECT_EQ(buildedQuery, expected + "\n");
}

// Test addData method
TEST_F(IndexerQueryTest, AddData)
{
    auto buildedQuery = IndexerQuery::bulkIndex("test-index", "123", R"({"field1":"value1","field2":42})");
    std::string expected = R"({"index":{"_index":"test-index","_id":"123"}})"
                           "\n"
                           R"({"field1":"value1","field2":42})"
                           "\n";
    EXPECT_EQ(buildedQuery, expected);
}

TEST_F(IndexerQueryTest, AddDataWithoutId)
{
    auto buildedQuery = IndexerQuery::bulkIndex("test-index", "", R"({"field1":"value1","field2":42})");
    std::string expected = R"({"index":{"_index":"test-index"}})"
                           "\n"
                           R"({"field1":"value1","field2":42})"
                           "\n";
    EXPECT_EQ(buildedQuery, expected);
}

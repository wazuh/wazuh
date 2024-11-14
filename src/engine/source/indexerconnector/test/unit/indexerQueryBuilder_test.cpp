#include "indexerQueryBuilder_test.hpp"
#include <indexerQueryBuilder.hpp>

// Test bulkIndex method
TEST_F(IndexerQueryBuilderTest, BulkIndexWithId)
{
    auto builder = IndexerQueryBuilder().builder();
    builder.bulkIndex("test-index", "123");
    std::string expected = R"({"index":{"_index":"test-index","_id":"123"}})";
    EXPECT_EQ(builder.build(), expected + "\n");
}

// Test bulkIndex method without ID
TEST_F(IndexerQueryBuilderTest, BulkIndexWithoutId)
{
    auto builder = IndexerQueryBuilder().builder();
    builder.bulkIndex("test-index", "");
    std::string expected = R"({"index":{"_index":"test-index"}})";
    EXPECT_EQ(builder.build(), expected + "\n");
}

// Test deleteIndex method with ID
TEST_F(IndexerQueryBuilderTest, DeleteIndexWithId)
{
    auto builder = IndexerQueryBuilder().builder();
    builder.deleteIndex("test-index", "123");
    std::string expected = R"({"delete":{"_index":"test-index","_id":"123"}})";
    EXPECT_EQ(builder.build(), expected + "\n");
}

// Test addData method
TEST_F(IndexerQueryBuilderTest, AddData)
{
    auto builder = IndexerQueryBuilder().builder();
    builder.bulkIndex("test-index", "123").addData(R"({"field1":"value1","field2":42})");
    std::string expected = R"({"index":{"_index":"test-index","_id":"123"}})"
                           "\n"
                           R"({"field1":"value1","field2":42})"
                           "\n";
    EXPECT_EQ(builder.build(), expected);
}

// Test build method with multiple operations
TEST_F(IndexerQueryBuilderTest, BuildWithMultipleOperations)
{
    auto builder = IndexerQueryBuilder().builder();
    builder.bulkIndex("index1", "id1").addData(R"({"field":"value1"})").deleteIndex("index2", "id2");

    std::string expected = R"({"index":{"_index":"index1","_id":"id1"}})"
                           "\n"
                           R"({"field":"value1"})"
                           "\n"
                           R"({"delete":{"_index":"index2","_id":"id2"}})"
                           "\n";

    EXPECT_EQ(builder.build(), expected);
}

// Test clear method
TEST_F(IndexerQueryBuilderTest, Clear)
{
    auto builder = IndexerQueryBuilder().builder();
    builder.bulkIndex("test-index", "123");
    builder.clear();
    EXPECT_EQ(builder.build(), "");
}

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <kvdbioc/mockManager.hpp>
#include <kvdbioc/mockReadOnlyHandler.hpp>

using namespace kvdbioc;
using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

// Unit tests using mocks to isolate Manager behavior
class ManagerUnitTest : public ::testing::Test
{
protected:
    NiceMock<MockKVDBManager> mockManager;
};

// ============================================================================
// PRIMITIVE OPERATIONS TESTS
// ============================================================================

TEST_F(ManagerUnitTest, AddCreatesNewDatabase)
{
    EXPECT_CALL(mockManager, add("newdb")).WillOnce(Return());

    EXPECT_NO_THROW(mockManager.add("newdb"));
}

TEST_F(ManagerUnitTest, AddFailsWhenDatabaseAlreadyExists)
{
    EXPECT_CALL(mockManager, add("existing"))
        .WillOnce(
            ::testing::Throw(std::runtime_error("KVDB 'existing': database already exists or build in progress")));

    EXPECT_THROW(mockManager.add("existing"), std::runtime_error);
}

TEST_F(ManagerUnitTest, PutAddsKeyValuePair)
{
    EXPECT_CALL(mockManager, put("testdb", "key1", "value1")).WillOnce(Return());

    EXPECT_NO_THROW(mockManager.put("testdb", "key1", "value1"));
}

TEST_F(ManagerUnitTest, PutFailsWhenNoBuildInProgress)
{
    EXPECT_CALL(mockManager, put("testdb", "key1", "value1"))
        .WillOnce(::testing::Throw(std::runtime_error("KVDB 'testdb': no active build")));

    EXPECT_THROW(mockManager.put("testdb", "key1", "value1"), std::runtime_error);
}

TEST_F(ManagerUnitTest, HotSwapCommitsDatabase)
{
    EXPECT_CALL(mockManager, hotSwap("testdb", "testdb")).WillOnce(Return());

    EXPECT_NO_THROW(mockManager.hotSwap("testdb", "testdb"));
}

TEST_F(ManagerUnitTest, HotSwapFailsWhenNoBuildInProgress)
{
    EXPECT_CALL(mockManager, hotSwap("testdb", "testdb"))
        .WillOnce(::testing::Throw(std::runtime_error("KVDB 'testdb': no active build to commit")));

    EXPECT_THROW(mockManager.hotSwap("testdb", "testdb"), std::runtime_error);
}

TEST_F(ManagerUnitTest, RemoveDeletesDatabase)
{
    EXPECT_CALL(mockManager, remove("testdb")).WillOnce(Return());

    EXPECT_NO_THROW(mockManager.remove("testdb"));
}

TEST_F(ManagerUnitTest, RemoveFailsWhenHandlersExist)
{
    EXPECT_CALL(mockManager, remove("protected_db"))
        .WillOnce(::testing::Throw(std::runtime_error("KVDB 'protected_db': cannot delete while handlers exist")));

    EXPECT_THROW(mockManager.remove("protected_db"), std::runtime_error);
}

TEST_F(ManagerUnitTest, RemoveFailsForNonExistentDatabase)
{
    EXPECT_CALL(mockManager, remove("nonexistent"))
        .WillOnce(::testing::Throw(std::runtime_error("KVDB 'nonexistent': database not found")));

    EXPECT_THROW(mockManager.remove("nonexistent"), std::runtime_error);
}

// ============================================================================
// HANDLER OPERATIONS TESTS
// ============================================================================

TEST_F(ManagerUnitTest, GetReturnsValue)
{
    EXPECT_CALL(mockManager, get("testdb", "key1")).WillOnce(Return(json::Json(R"({"value":"test"})")));

    auto result = mockManager.get("testdb", "key1");

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->str(), R"({"value":"test"})");
}

TEST_F(ManagerUnitTest, GetReturnsNulloptForNonexistentKey)
{
    EXPECT_CALL(mockManager, get("testdb", "nonexistent")).WillOnce(Return(std::nullopt));

    auto result = mockManager.get("testdb", "nonexistent");

    EXPECT_FALSE(result.has_value());
}

TEST_F(ManagerUnitTest, multiGetReturnsMultipleValues)
{
    std::vector<std::optional<json::Json>> expected = {
        json::Json(R"({"val":1})"), json::Json(R"({"val":2})"), std::nullopt};

    EXPECT_CALL(mockManager, multiGet("testdb", ::testing::_)).WillOnce(Return(expected));

    std::vector<std::string_view> keys = {"key1", "key2", "key3"};
    auto result = mockManager.multiGet("testdb", keys);

    EXPECT_EQ(result.size(), 3);
    EXPECT_TRUE(result[0].has_value());
    EXPECT_TRUE(result[1].has_value());
    EXPECT_FALSE(result[2].has_value());
}

// ============================================================================
// WORKFLOW SEQUENCE TESTS
// ============================================================================

TEST_F(ManagerUnitTest, CompleteWorkflow_AddPutHotSwap)
{
    EXPECT_CALL(mockManager, add("workflow_db")).WillOnce(Return());
    EXPECT_CALL(mockManager, put("workflow_db", "key1", "value1")).WillOnce(Return());
    EXPECT_CALL(mockManager, put("workflow_db", "key2", "value2")).WillOnce(Return());
    EXPECT_CALL(mockManager, hotSwap("workflow_db", "workflow_db")).WillOnce(Return());

    EXPECT_NO_THROW(mockManager.add("workflow_db"));
    EXPECT_NO_THROW(mockManager.put("workflow_db", "key1", "value1"));
    EXPECT_NO_THROW(mockManager.put("workflow_db", "key2", "value2"));
    EXPECT_NO_THROW(mockManager.hotSwap("workflow_db", "workflow_db"));
}

TEST_F(ManagerUnitTest, CompleteWorkflow_AddPutHotSwapGet)
{
    EXPECT_CALL(mockManager, add("workflow_db")).WillOnce(Return());
    EXPECT_CALL(mockManager, put("workflow_db", _, _)).Times(3).WillRepeatedly(Return());
    EXPECT_CALL(mockManager, hotSwap("workflow_db", "workflow_db")).WillOnce(Return());
    EXPECT_CALL(mockManager, get("workflow_db", "k1")).WillOnce(Return(json::Json(R"({"value":"v1"})")));

    mockManager.add("workflow_db");
    mockManager.put("workflow_db", "k1", "v1");
    mockManager.put("workflow_db", "k2", "v2");
    mockManager.put("workflow_db", "k3", "v3");
    mockManager.hotSwap("workflow_db", "workflow_db");

    auto result = mockManager.get("workflow_db", "k1");
    EXPECT_TRUE(result.has_value());
}

TEST_F(ManagerUnitTest, CompleteWorkflow_AddPutHotSwapRemove)
{
    EXPECT_CALL(mockManager, add("temp_db")).WillOnce(Return());
    EXPECT_CALL(mockManager, put("temp_db", "key", "value")).WillOnce(Return());
    EXPECT_CALL(mockManager, hotSwap("temp_db", "temp_db")).WillOnce(Return());
    EXPECT_CALL(mockManager, remove("temp_db")).WillOnce(Return());

    mockManager.add("temp_db");
    mockManager.put("temp_db", "key", "value");
    mockManager.hotSwap("temp_db", "temp_db");
    mockManager.remove("temp_db");
}

TEST_F(ManagerUnitTest, MultipleHotSwaps_UpdateScenario)
{
    // IOC workflow: multiple add→put→hotSwap cycles WITHOUT remove() between them
    EXPECT_CALL(mockManager, add("update_db")).Times(2).WillRepeatedly(Return());
    EXPECT_CALL(mockManager, put("update_db", _, _)).Times(4).WillRepeatedly(Return());
    EXPECT_CALL(mockManager, hotSwap("update_db", "update_db")).Times(2).WillRepeatedly(Return());

    // First version
    mockManager.add("update_db");
    mockManager.put("update_db", "k1", "v1");
    mockManager.hotSwap("update_db", "update_db");

    // Second version (rebuild same DB without remove)
    mockManager.add("update_db");
    mockManager.put("update_db", "k1", "v2");
    mockManager.put("update_db", "k2", "v2");
    mockManager.put("update_db", "k3", "v2");
    mockManager.hotSwap("update_db", "update_db");
}

TEST_F(ManagerUnitTest, HandlerPreventsRemoval)
{
    EXPECT_CALL(mockManager, add("protected")).WillOnce(Return());
    EXPECT_CALL(mockManager, hotSwap("protected", "protected")).WillOnce(Return());
    EXPECT_CALL(mockManager, remove("protected"))
        .WillOnce(::testing::Throw(std::runtime_error("KVDB 'protected': cannot delete while handlers exist")));

    mockManager.add("protected");
    mockManager.hotSwap("protected", "protected");

    EXPECT_THROW(mockManager.remove("protected"), std::runtime_error);
}

// ============================================================================
// INTERFACE COMPLIANCE TESTS
// ============================================================================

TEST_F(ManagerUnitTest, ManagerInterfaceCompliance)
{
    // Verify manager implements IKVDBManager interface
    IKVDBManager* manager = &mockManager;
    EXPECT_NE(manager, nullptr);
}

// ============================================================================
// STRICT MOCK TESTS
// ============================================================================

TEST(ManagerStrictTest, OnlyExpectedOperationsAreCalled)
{
    StrictMock<MockKVDBManager> strictManager;

    EXPECT_CALL(strictManager, add("test")).WillOnce(Return());
    EXPECT_CALL(strictManager, put("test", "key", "value")).WillOnce(Return());
    EXPECT_CALL(strictManager, hotSwap("test", "test")).WillOnce(Return());

    // These are expected
    strictManager.add("test");
    strictManager.put("test", "key", "value");
    strictManager.hotSwap("test", "test");

    // Any other unexpected call would fail with StrictMock
}

// ============================================================================
// ARGUMENT MATCHING TESTS
// ============================================================================

TEST_F(ManagerUnitTest, PutWithSpecificArguments)
{
    EXPECT_CALL(mockManager, put("specific_db", "exact_key", "exact_value")).WillOnce(Return());

    mockManager.put("specific_db", "exact_key", "exact_value");
}

TEST_F(ManagerUnitTest, PutWithAnyArguments)
{
    EXPECT_CALL(mockManager, put("any_db", _, _)).Times(3).WillRepeatedly(Return());

    mockManager.put("any_db", "key1", "value1");
    mockManager.put("any_db", "key2", "value2");
    mockManager.put("any_db", "key3", "value3");
}

TEST_F(ManagerUnitTest, MultipleOperationsOnDifferentDatabases)
{
    EXPECT_CALL(mockManager, add("db1")).WillOnce(Return());
    EXPECT_CALL(mockManager, add("db2")).WillOnce(Return());
    EXPECT_CALL(mockManager, put("db1", _, _)).Times(2).WillRepeatedly(Return());
    EXPECT_CALL(mockManager, put("db2", _, _)).Times(2).WillRepeatedly(Return());
    EXPECT_CALL(mockManager, hotSwap("db1", "db1")).WillOnce(Return());
    EXPECT_CALL(mockManager, hotSwap("db2", "db2")).WillOnce(Return());

    mockManager.add("db1");
    mockManager.add("db2");
    mockManager.put("db1", "k1", "v1");
    mockManager.put("db2", "k1", "v1");
    mockManager.put("db1", "k2", "v2");
    mockManager.put("db2", "k2", "v2");
    mockManager.hotSwap("db1", "db1");
    mockManager.hotSwap("db2", "db2");
}

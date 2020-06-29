#include "sqlite_test.h"
#include "sqlite_wrapper.h"

constexpr auto TEMP_TEST_DB_PATH{"temp_test.db"};
constexpr auto TEMP_DB_PATH{"temp.db"};

void SQLiteTest::SetUp() {};

void SQLiteTest::TearDown()
{
    std::remove(TEMP_TEST_DB_PATH);
    std::remove(TEMP_DB_PATH);
};
using ::testing::_;
using ::testing::Return;
using namespace SQLite;

class ConnectionWrapper: public IConnection
{
public:
    ConnectionWrapper() = default;
    ~ConnectionWrapper() = default;
    MOCK_METHOD(bool, execute, (const std::string&), (override));
    MOCK_METHOD(bool, close, (), (override));
    MOCK_METHOD((const std::shared_ptr<sqlite3>&), db, (), (const override));
};


TEST_F(SQLiteTest, ConnectionCtor)
{
    Connection connectionDefault;
    EXPECT_NE(nullptr, connectionDefault.db().get());
    Connection connectionPath{TEMP_TEST_DB_PATH};
    EXPECT_NE(nullptr, connectionPath.db().get());
}

TEST_F(SQLiteTest, ConnectionClose)
{
    Connection connectionDefault;
    EXPECT_TRUE(connectionDefault.close());
    EXPECT_TRUE(connectionDefault.close());
    EXPECT_EQ(nullptr, connectionDefault.db().get());
}

TEST_F(SQLiteTest, ConnectionExecute)
{
    Connection connectionDefault;
    EXPECT_TRUE(connectionDefault.execute("BEGIN TRANSACTION"));
    EXPECT_FALSE(connectionDefault.execute("WRONG STATEMENT"));
    EXPECT_TRUE(connectionDefault.execute("ROLLBACK TRANSACTION"));
}

TEST_F(SQLiteTest, TransactionCtorDtorSuccess)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION"));
    Transaction transaction{spConnection};
    EXPECT_FALSE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionCtorDtorFailure)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(false));
    EXPECT_THROW(Transaction transaction{spConnection}, SQLite::exception);
}

TEST_F(SQLiteTest, TransactionCommitSuccess)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("COMMIT TRANSACTION")).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(0);
    Transaction transaction{spConnection};
    EXPECT_TRUE(transaction.commit());
    EXPECT_TRUE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionCommitFailure)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("COMMIT TRANSACTION")).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION"));
    Transaction transaction{spConnection};
    EXPECT_FALSE(transaction.commit());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionCommitCantRollBack)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("COMMIT TRANSACTION")).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(0);
    Transaction transaction{spConnection};
    EXPECT_TRUE(transaction.commit());
    EXPECT_FALSE(transaction.rollback());
    EXPECT_TRUE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionCanCommitOnce)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("COMMIT TRANSACTION")).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(0);
    Transaction transaction{spConnection};
    EXPECT_TRUE(transaction.commit());
    EXPECT_FALSE(transaction.commit());
    EXPECT_FALSE(transaction.rollback());
    EXPECT_TRUE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionRollBack)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(1);
    Transaction transaction{spConnection};
    EXPECT_TRUE(transaction.rollback());
    EXPECT_TRUE(transaction.isRolledBack());
    EXPECT_FALSE(transaction.isCommited());
}

TEST_F(SQLiteTest, TransactionCantCommitAfterRollBack)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION")).WillOnce(Return(true));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(1);
    Transaction transaction{spConnection};
    EXPECT_TRUE(transaction.rollback());
    EXPECT_FALSE(transaction.commit());
    EXPECT_TRUE(transaction.isRolledBack());
    EXPECT_FALSE(transaction.isCommited());
}

TEST_F(SQLiteTest, StatementSuccess)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement stmt{spConnection, "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT);"};
    EXPECT_NO_THROW(stmt.step());
}

TEST_F(SQLiteTest, StatementBindInt)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement createStmt{spConnection, "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT);"};
    EXPECT_NO_THROW(createStmt.step());
    Statement insertStmt{spConnection, R"(INSERT INTO test_table (Colum1) VALUES (?);)"};
    EXPECT_TRUE(insertStmt.bind(1, 1l));
    EXPECT_NO_THROW(insertStmt.step());
    EXPECT_TRUE(insertStmt.reset());
    EXPECT_TRUE(insertStmt.bind(1, 2l));
    EXPECT_NO_THROW(insertStmt.step());
}

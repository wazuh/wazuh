/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 20, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sqlite_test.h"
#include "sqlite_wrapper.h"
#include "db_exception.h"

constexpr auto TEMP_TEST_DB_PATH {"temp_test.db"};
constexpr auto TEMP_DB_PATH {"temp.db"};

void SQLiteTest::SetUp() {};

void SQLiteTest::TearDown()
{
    std::remove(TEMP_TEST_DB_PATH);
    std::remove(TEMP_DB_PATH);
};
using ::testing::_;
using ::testing::Return;
using namespace SQLite;
using namespace DbSync;

class ConnectionWrapper: public IConnection
{
    public:
        ConnectionWrapper() = default;
        ~ConnectionWrapper() = default;
        MOCK_METHOD(void, execute, (const std::string&), (override));
        MOCK_METHOD(void, close, (), (override));
        MOCK_METHOD(int64_t, changes, (), (const override));
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
    connectionDefault.close();
    EXPECT_EQ(nullptr, connectionDefault.db().get());
    EXPECT_THROW(connectionDefault.execute("BEGIN TRANSACTION"), sqlite_error);
}

TEST_F(SQLiteTest, ConnectionExecute)
{
    Connection connectionDefault;
    EXPECT_NO_THROW(connectionDefault.execute("BEGIN TRANSACTION"));
    EXPECT_THROW(connectionDefault.execute("WRONG STATEMENT"), sqlite_error);
    EXPECT_NO_THROW(connectionDefault.execute("ROLLBACK TRANSACTION"));
}
TEST_F(SQLiteTest, TransactionCtorDtorSuccess)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION"));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION"));
    Transaction transaction{spConnection};
    EXPECT_FALSE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionCommitSuccess)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION"));
    EXPECT_CALL(*pConnection, execute("COMMIT TRANSACTION")).Times(1);
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(0);
    Transaction transaction{spConnection};
    EXPECT_NO_THROW(transaction.commit());
    EXPECT_TRUE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionCommitCantRollBack)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION"));
    EXPECT_CALL(*pConnection, execute("COMMIT TRANSACTION")).Times(1);
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(0);
    Transaction transaction{spConnection};
    EXPECT_NO_THROW(transaction.commit());
    EXPECT_NO_THROW(transaction.rollback());
    EXPECT_TRUE(transaction.isCommited());
    EXPECT_FALSE(transaction.isRolledBack());
}

TEST_F(SQLiteTest, TransactionRollBack)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION"));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(1);
    Transaction transaction{spConnection};
    EXPECT_NO_THROW(transaction.rollback());
    EXPECT_TRUE(transaction.isRolledBack());
    EXPECT_FALSE(transaction.isCommited());
}

TEST_F(SQLiteTest, TransactionCantCommitAfterRollBack)
{
    ConnectionWrapper* pConnection{ new ConnectionWrapper };
    std::shared_ptr<IConnection> spConnection{ pConnection };
    EXPECT_CALL(*pConnection, execute("BEGIN TRANSACTION"));
    EXPECT_CALL(*pConnection, execute("ROLLBACK TRANSACTION")).Times(1);
    Transaction transaction{spConnection};
    EXPECT_NO_THROW(transaction.rollback());
    EXPECT_NO_THROW(transaction.commit());
    EXPECT_TRUE(transaction.isRolledBack());
    EXPECT_FALSE(transaction.isCommited());
}

TEST_F(SQLiteTest, StatementCtorSuccess)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement stmt{spConnection, "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT);"};
}

TEST_F(SQLiteTest, StatementCtorFailure)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    EXPECT_THROW(Statement stmt(spConnection, "WRONG STATEMENT"), sqlite_error);
}

TEST_F(SQLiteTest, StatementStep)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement stmt{spConnection, "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT);"};
    EXPECT_TRUE(stmt.step());
    stmt.reset();
    EXPECT_THROW(stmt.step(), sqlite_error);
}

TEST_F(SQLiteTest, StatementBindInt)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement createStmt
    {
        spConnection,
        "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT, Colum3 BIGINT, Colum4 BIGINT, Colum5 FLOAT);"
    };
    EXPECT_NO_THROW(createStmt.step());
    Statement insertStmt
    {
        spConnection,
        R"(INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5) VALUES (?,?,?,?,?);)"
    };
    EXPECT_NO_THROW(insertStmt.bind(1, 1));
    EXPECT_NO_THROW(insertStmt.bind(2, "1"));
    EXPECT_NO_THROW(insertStmt.bind(3, int64_t{1l}));
    EXPECT_NO_THROW(insertStmt.bind(4, uint64_t{1lu}));
    EXPECT_NO_THROW(insertStmt.bind(5, double_t{1.0}));
    EXPECT_TRUE(insertStmt.step());
    insertStmt.reset();
    EXPECT_NO_THROW(insertStmt.bind(1, 2));
    EXPECT_NO_THROW(insertStmt.bind(2, "2"));
    EXPECT_NO_THROW(insertStmt.bind(3, int64_t{2l}));
    EXPECT_NO_THROW(insertStmt.bind(4, uint64_t{2lu}));
    EXPECT_NO_THROW(insertStmt.bind(5, double_t{2.0}));
    EXPECT_TRUE(insertStmt.step());
}


TEST_F(SQLiteTest, ColumnCtor)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement createStmt
    {
        spConnection,
        "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT, Colum3 BIGINT, Colum4 BIGINT, Colum5 FLOAT);"
    };
    EXPECT_TRUE(createStmt.step());
    Statement insertStmt
    {
        spConnection, R"(INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5) VALUES (?,?,?,?,?);)"
    };
    auto spColumn{ insertStmt.column(1) };
    EXPECT_FALSE(spColumn->hasValue());
}


TEST_F(SQLiteTest, ColumnValue)
{
    std::shared_ptr<IConnection> spConnection{ new Connection };
    Statement createStmt
    {
        spConnection,
        R"(CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT, Colum3 BIGINT, Colum4 BIGINT, Colum5 FLOAT);)"
    };
    EXPECT_TRUE(createStmt.step());
    Statement insertStmt
    {
        spConnection, R"(INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5)  VALUES (1,"some text",2,3,4.0);)"
    };
    EXPECT_TRUE(insertStmt.step());
    Statement selectStmt
    {
        spConnection, R"(SELECT * FROM test_table;)"
    };
    EXPECT_TRUE(selectStmt.step());
    auto spColumn1{ selectStmt.column(0) };
    EXPECT_TRUE(spColumn1->hasValue());
    EXPECT_EQ(1, spColumn1->value(int32_t{}));
    EXPECT_EQ(SQLITE_INTEGER, spColumn1->type());

    auto spColumn2{ selectStmt.column(1) };
    EXPECT_TRUE(spColumn2->hasValue());
    EXPECT_EQ("some text", spColumn2->value(std::string{}));
    EXPECT_EQ(SQLITE3_TEXT, spColumn2->type());

    auto spColumn3{ selectStmt.column(2) };
    EXPECT_TRUE(spColumn3->hasValue());
    EXPECT_EQ(2l, spColumn3->value(int64_t{}));
    EXPECT_EQ(SQLITE_INTEGER, spColumn3->type());

    auto spColumn4{ selectStmt.column(3) };
    EXPECT_TRUE(spColumn4->hasValue());
    EXPECT_EQ(3lu, spColumn4->value(uint64_t{}));
    EXPECT_EQ(SQLITE_INTEGER, spColumn4->type());

    auto spColumn5{ selectStmt.column(4) };
    EXPECT_TRUE(spColumn5->hasValue());
    EXPECT_DOUBLE_EQ(4.0, spColumn5->value(double_t{}));
    EXPECT_EQ(SQLITE_FLOAT, spColumn5->type());
}

TEST_F(SQLiteTest, StatementExpand)
{
    std::shared_ptr<IConnection> spConnection = std::make_shared<Connection>();
    Statement createStmt
    {
        spConnection,
        "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT, Colum3 BIGINT, Colum4 BIGINT, Colum5 FLOAT);"
    };
    createStmt.step();
    Statement selectStmt
    {
        spConnection,
        R"(INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5) VALUES (?,?,?,?,?);)"
    };
    const auto expectedStringStmt{ selectStmt.expand() };
    EXPECT_EQ(expectedStringStmt, "INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5) VALUES (NULL,NULL,NULL,NULL,NULL);");
}

TEST_F(SQLiteTest, StatementExpandBind)
{
    std::shared_ptr<IConnection> spConnection = std::make_shared<Connection>();
    Statement createStmt
    {
        spConnection,
        "CREATE TABLE test_table (Colum1 INTEGER, Colum2 TEXT, Colum3 BIGINT, Colum4 BIGINT, Colum5 FLOAT);"
    };
    createStmt.step();
    Statement insertStmt
    {
        spConnection,
        R"(INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5) VALUES (?,?,?,?,?);)"
    };
    insertStmt.bind(2, "bar");
    insertStmt.bind(3, 1000);
    const auto expectedStringStmt{ insertStmt.expand() };
    EXPECT_EQ(expectedStringStmt, "INSERT INTO test_table (Colum1, Colum2, Colum3, Colum4, Colum5) VALUES (NULL,'bar',1000,NULL,NULL);");
}

#pragma once
#include "isqlite_wrapper.h"
#include "sqlite3.h"

#include <string>
#include <memory>
namespace SQLite {

class Connection : public IConnection
{
public:
    Connection();
    virtual ~Connection();
    Connection(const std::string& path);
    
    bool Execute(const std::string& query) override;
    bool Close() override;
    sqlite3* GetDBInstance() override;
private:
    sqlite3* m_db_instance;
    std::string m_path;
};


class Transaction : public ITransaction
{
public:
    virtual ~Transaction();
    Transaction(std::shared_ptr<IConnection>& connection);
    
    bool Commit() override;
    bool Rollback() override;
private:
    std::shared_ptr<IConnection> m_connection;
    bool m_rollbacked;
    bool m_commited;
    bool m_started;
};

class Column : public IColumn {
public:
    virtual ~Column() = default;
    Column(sqlite3_stmt* stmt, const int32_t index);

    bool IsNullValue();
    int32_t Int();
    uint64_t UInt64();
    int64_t Int64();
    double Double();
    std::string String();
private:
    sqlite3_stmt* m_stmt;
    int32_t m_index;
};

class Statement : public IStatement 
{
public:
    virtual ~Statement();
    Statement(std::shared_ptr<IConnection>& connection, const std::string& query);

    bool Step();
    bool Reset() override;

    bool Bind(const int32_t index, const int32_t value) override;
    bool Bind(const int32_t index, const uint64_t value) override;
    bool Bind(const int32_t index, const int64_t value) override;
    bool Bind(const int32_t index, const std::string value) override;
    bool Bind(const int32_t index, const double value) override;

    IColumn GetColumn(const int32_t index) override;

private:
    sqlite3_stmt* m_stmt;

};
}


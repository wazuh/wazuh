#pragma once
#include <string>
#include <sqlite3.h>

namespace SQLite {
class IConnection 
{
public:
    virtual bool Close() = 0;
    virtual bool Execute(const std::string& query) = 0;
    virtual sqlite3* GetDBInstance() = 0;
};

class ITransaction 
{
public:
    virtual bool Commit() = 0;
    virtual bool Rollback() = 0;
};

class IColumn {
    virtual bool IsNullValue() { return true; }
    virtual int32_t Int() { return 0l; }
    virtual uint64_t UInt64() { return 0ull; }
    virtual int64_t Int64() { return 0ll; }
    virtual double Double() { return .0f; }
    virtual std::string String() { return std::string(); } 
};

class IStatement 
{
public:
    virtual bool Step() = 0;
    virtual bool Bind(const int32_t index, const int32_t value) = 0;
    virtual bool Bind(const int32_t index, const uint64_t value) = 0;
    virtual bool Bind(const int32_t index, const int64_t value) = 0;
    virtual bool Bind(const int32_t index, const std::string value) = 0;
    virtual bool Bind(const int32_t index, const double value) = 0;

    virtual IColumn GetColumn(const int32_t index) = 0;
    virtual bool Reset() = 0;


};

}
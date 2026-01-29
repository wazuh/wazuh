#ifndef _KVDBIOC_DBINSTANCE_HPP
#define _KVDBIOC_DBINSTANCE_HPP

#include <memory>
#include <string>
#include <string_view>

#include <rocksdb/db.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <fmt/format.h>

namespace kvdb
{

class DbInstance
{
public:
    explicit DbInstance(std::string path)
        : m_path(std::move(path))
    {
        rocksdb::DB* raw = nullptr;
        auto st = rocksdb::DB::OpenForReadOnly(rocksdb::Options {}, m_path, &raw);
        if (!st.ok())
        {
            throw std::runtime_error(st.ToString());
        }
        m_db.reset(raw);
    }

    ~DbInstance() = default;

    DbInstance(const DbInstance&) = delete;
    DbInstance& operator=(const DbInstance&) = delete;
    DbInstance(DbInstance&&) = delete;
    DbInstance& operator=(DbInstance&&) = delete;

    json::Json get(std::string_view key) const;

    const std::string& path() const noexcept { return m_path; }

private:
    struct DbDeleter
    {
        void operator()(rocksdb::DB* p) const noexcept { delete p; }
    };
    std::unique_ptr<rocksdb::DB, DbDeleter> m_db;
    std::string m_path;
};

} // namespace kvdb

#endif // _KVDBIOC_DBINSTANCE_HPP

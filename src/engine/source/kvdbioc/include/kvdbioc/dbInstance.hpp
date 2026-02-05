#ifndef _KVDBIOC_DBINSTANCE_HPP
#define _KVDBIOC_DBINSTANCE_HPP

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include <rocksdb/convenience.h>
#include <rocksdb/db.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <fmt/format.h>

namespace kvdbioc
{

class DbInstance
{
public:
    // Constructor for taking ownership of an already-open DB (r/w mode)
    explicit DbInstance(std::string path, rocksdb::DB* db)
        : m_path(std::move(path))
        , m_db(db)
        , m_shouldDeleteOnDestroy(false)
    {
    }

    ~DbInstance()
    {
        rocksdb::FlushOptions flush_opts;
        flush_opts.wait = true;

        auto status = m_db->Flush(flush_opts);
        if (!status.ok())
        {
            LOG_WARNING("Flush failed for '{}': {}.", m_path, status.ToString());
        }

        // Close RocksDB
        m_db.reset();

        // Only delete directory if marked for deletion (retired instances)
        if (!m_shouldDeleteOnDestroy)
        {
            return;
        }

        const std::filesystem::path instPath {m_path}; // m_path string -> fs::path

        // Delete the instance directory
        std::error_code ec;
        std::filesystem::remove_all(instPath, ec);
        if (ec)
        {
            LOG_WARNING("Failed to delete directory '{}': {}.", instPath.string(), ec.message());
        }

        // Try to delete the parent directory (DB) ONLY if it is empty: .../ioc-production
        const std::filesystem::path parent = instPath.parent_path();
        if (!parent.empty())
        {
            std::error_code ec2;
            std::filesystem::remove(parent, ec2); // remove() only deletes if empty
        }
    }

    DbInstance(const DbInstance&) = delete;
    DbInstance& operator=(const DbInstance&) = delete;
    DbInstance(DbInstance&&) = delete;
    DbInstance& operator=(DbInstance&&) = delete;

    std::optional<json::Json> get(std::string_view key) const;

    std::vector<std::optional<json::Json>> multiGet(const std::vector<std::string_view>& keys) const;

    void put(std::string_view key, std::string_view value);

    const std::string& path() const noexcept { return m_path; }

    std::string getPath() const { return m_path; }

    // Mark this instance for deletion when destroyed (called by manager for retired instances)
    void markForDeletion() { m_shouldDeleteOnDestroy = true; }

private:
    struct DbDeleter
    {
        void operator()(rocksdb::DB* p) const noexcept
        {
            if (p)
            {
                // CRITICAL: Cancel all background work and WAIT for completion
                // This prevents race conditions when destroying DB instances
                // wait=true blocks until all RocksDB threads complete
                rocksdb::CancelAllBackgroundWork(p, true);

                // Sync all data to disk before closing
                rocksdb::FlushOptions flush_opts;
                flush_opts.wait = true;
                flush_opts.allow_write_stall = true;
                auto flush_status = p->Flush(flush_opts);
                // Ignore flush errors in destructor (can't throw)

                // Close DB handle
                auto close_status = p->Close();
                // Ignore close errors in destructor (can't throw)

                // Delete the DB object
                delete p;
            }
        }
    };
    std::unique_ptr<rocksdb::DB, DbDeleter> m_db;
    std::string m_path;
    bool m_shouldDeleteOnDestroy; // Only true for retired instances
};

} // namespace kvdbioc

#endif // _KVDBIOC_DBINSTANCE_HPP

#ifndef _GEO_DBINSTANCE_HPP
#define _GEO_DBINSTANCE_HPP

#include <stdexcept>
#include <string>

#include <maxminddb.h>

#include <geo/imanager.hpp>

namespace geo
{

class DbInstance
{
public:
    DbInstance(std::string path, std::string hash, std::string createdAt, Type type)
        : m_path(std::move(path))
        , m_hash(std::move(hash))
        , m_createdAt(std::move(createdAt))
        , m_type(type)
    {
        int status = MMDB_open(m_path.c_str(), MMDB_MODE_MMAP, &m_mmdb);
        if (status != MMDB_SUCCESS)
        {
            throw std::runtime_error(MMDB_strerror(status));
        }
    }

    ~DbInstance() { MMDB_close(&m_mmdb); }

    DbInstance(const DbInstance&) = delete;
    DbInstance& operator=(const DbInstance&) = delete;
    DbInstance(DbInstance&&) = delete;
    DbInstance& operator=(DbInstance&&) = delete;

    const MMDB_s& mmdb() const noexcept { return m_mmdb; }
    const std::string& path() const noexcept { return m_path; }
    const std::string& hash() const noexcept { return m_hash; }
    const std::string& createdAt() const noexcept { return m_createdAt; }
    Type type() const noexcept { return m_type; }

private:
    MMDB_s m_mmdb{};
    std::string m_path;
    std::string m_hash;
    std::string m_createdAt;
    Type m_type;
};

} // namespace geo

#endif

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
    DbInstance(std::string path, Type type)
        : m_path(std::move(path))
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
    Type type() const noexcept { return m_type; }

private:
    MMDB_s m_mmdb{};
    std::string m_path;
    Type m_type;
};

} // namespace geo

#endif

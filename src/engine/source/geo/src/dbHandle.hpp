#ifndef _GEO_DBHANDLE_HPP
#define _GEO_DBHANDLE_HPP

#include <atomic>
#include <memory>

#include "dbInstance.hpp"

namespace geo
{

class DbHandle
{
public:
    std::shared_ptr<const DbInstance> load() const noexcept { return std::atomic_load(&m_current); }

    void store(std::shared_ptr<const DbInstance> next) noexcept { std::atomic_store(&m_current, std::move(next)); }

private:
    std::shared_ptr<const DbInstance> m_current;
};

} // namespace geo

#endif

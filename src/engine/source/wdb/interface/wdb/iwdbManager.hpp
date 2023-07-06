#ifndef _WDB_IWDB_MANAGER_HPP
#define _WDB_IWDB_MANAGER_HPP

#include <memory>

#include <wdb/iwdbHandler.hpp>

namespace wazuhdb
{

class IWDBManager
{
public:
    virtual ~IWDBManager() = default;

    virtual std::shared_ptr<IWDBHandler> connection() = 0;
};

} // namespace wazuhdb

#endif // _WDB_IWDB_MANAGER_HPP

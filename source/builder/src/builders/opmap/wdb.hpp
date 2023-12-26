#ifndef _OP_BUILDER_WDB_SYNC_H
#define _OP_BUILDER_WDB_SYNC_H

#include <wdb/iwdbManager.hpp>

#include "builders/types.hpp"

namespace builder::builders::opmap
{

/**
 * @brief Executes query on WDB returning the status.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression true when executes without any problem, false otherwise.
 */
MapBuilder getWdbUpdateBuilder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager);

/**
 * @brief Executes query on WDB returning the payload.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression when true returns string of payload, false none.
 */
MapBuilder getWdbQueryBuilder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager);

} // namespace builder::builders::opmap

#endif // _OP_BUILDER_WDB_SYNC_H

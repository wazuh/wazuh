#ifndef _OP_BUILDER_WDB_SYNC_H
#define _OP_BUILDER_WDB_SYNC_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"
#include <defs/idefinitions.hpp>
#include <utils/stringUtils.hpp>
#include <wdb/wdb.hpp>

namespace builder::internals::builders
{

/**
 * @brief Executes query on WDB returning the status.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression true when executes without any problem, false otherwise.
 */
base::Expression opBuilderWdbUpdate(const std::string& targetField,
                                    const std::string& rawName,
                                    const std::vector<std::string>& rawParameters,
                                    std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Executes query on WDB returning the payload.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression when true returns string of payload, false none.
 */
base::Expression opBuilderWdbQuery(const std::string& targetField,
                                   const std::string& rawName,
                                   const std::vector<std::string>& rawParameters,
                                   std::shared_ptr<defs::IDefinitions> definitions);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_WDB_SYNC_H

#ifndef _OP_BUILDER_KVDB_H
#define _OP_BUILDER_KVDB_H

#include <any>
#include <memory>

#include <defs/idefinitions.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <schemf/ischema.hpp>

#include "expression.hpp"
#include "registry.hpp"

namespace builder::internals::builders
{

using namespace kvdbManager;

/**
 * @brief Common builder for KVDB get operations
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param merge
 * @return base::Expression
 */
base::Expression KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                         const std::string& kvdbScopeName,
                         const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions,
                         bool merge);

/**
 * @brief Builder for KVDB set operation
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @return base::Expression
 */
base::Expression KVDBSet(std::shared_ptr<IKVDBManager> kvdbManager,
                         const std::string& kvdbScopeName,
                         const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Builder for KVDB delete operation
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression
 */
base::Expression KVDBDelete(std::shared_ptr<IKVDBManager> kvdbManager,
                            const std::string& kvdbScopeName,
                            const std::string& targetField,
                            const std::string& rawName,
                            const std::vector<std::string>& rawParameters,
                            std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Builds KVDB extract function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBGet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Builds KVDB extract and merge function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief get the KVDB match function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Get the KVDB not-match function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Get the KVDB Set function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBSet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Delete a KVDB function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBDelete(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Get the KVDB Get Array function helper builder
 *
 * @param kvdbManager KVDB Manager
 * @param kvdbScopeName KVDB Scope Name
 * @param schema Schema
 *
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBGetArray(std::shared_ptr<IKVDBManager> kvdbManager,
                                       const std::string& kvdbScopeName,
                                       std::shared_ptr<schemf::ISchema> schema);

/**
 * @brief Builds helper BitmaskToTable, that maps a bitmask to a table of values.
 * <field>: kvdb_decode_bitmask(KVDB_name, keyKVDB, $mask)
 *
 * The table should be a object with the following format  -> "bit position in decimal": JsonValue().
 * {
 *		"1": "value1",
 *		"2": "value2",
 *		"3": "value3",
 *      "4": "value4",
 *      ...
 *      "31": "value31",
 *      "32": "value32",
 *      ...
 *      "64": "value64",
 *	}
 *
 * If the bit position is not set, it will be ignored.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition.
 * @param definitions handler with definitions
 * @param kvdbManager KVDB Manager
 * @param kvdbScopeName KVDB Scope Name
 * @param schema schema to validate fields
 * @return base::Expression The Lifter with the SHA1 hash.
 * @throw std::runtime_error if the parameter size is not one.
 */
base::Expression OpBuilderHelperKVDBDecodeBitmask(const std::string& targetField,
                                                  const std::string& rawName,
                                                  const std::vector<std::string>& rawParameters,
                                                  std::shared_ptr<defs::IDefinitions> definitions,
                                                  std::shared_ptr<IKVDBManager> kvdbManager,
                                                  const std::string& kvdbScopeName,
                                                  std::shared_ptr<schemf::ISchema> schema);

/**
 * @brief Get the 'kvdb_decode_bitmask' function helper builder
 *
 * @param kvdbManager KVDB Manager
 * @param kvdbScopeName KVDB Scope
 * @param schema schema to validate fields
 * @return HelperBuilder The builder of the helper.
 */
HelperBuilder getOpBuilderHelperKVDBDecodeBitmask(std::shared_ptr<IKVDBManager> kvdbManager,
                                                  const std::string& kvdbScopeName,
                                                  std::shared_ptr<schemf::ISchema> schema);

} // namespace builder::internals::builders

// namespace builder::internals::builders

#endif // _OP_BUILDER_MAP_H

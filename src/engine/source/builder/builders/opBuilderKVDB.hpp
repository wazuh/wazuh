#ifndef _OP_BUILDER_KVDB_H
#define _OP_BUILDER_KVDB_H

#include <any>
#include <memory>

#include <defs/idefinitions.hpp>
#include <kvdb/kvdbManager.hpp>

#include "expression.hpp"
#include "registry.hpp"

namespace builder::internals::builders
{

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
base::Expression KVDBGet(const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions,
                         bool merge,
                         std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

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
base::Expression KVDBSet(const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions,
                         std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

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
base::Expression KVDBDelete(const std::string& targetField,
                            const std::string& rawName,
                            const std::vector<std::string>& rawParameters,
                            std::shared_ptr<defs::IDefinitions> definitions,
                            std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

/**
 * @brief Builds KVDB extract function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBGet(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

/**
 * @brief Builds KVDB extract and merge function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

/**
 * @brief get the KVDB match function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBMatch(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

/**
 * @brief Get the KVDB not-match function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

/**
 * @brief Get the KVDB Set function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBSet(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

/**
 * @brief Delete a KVDB function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
HelperBuilder getOpBuilderKVDBDelete(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

} // namespace builder::internals::builders

// namespace builder::internals::builders

#endif // _OP_BUILDER_MAP_H

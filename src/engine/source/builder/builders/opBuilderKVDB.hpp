#ifndef _OP_BUILDER_KVDB_H
#define _OP_BUILDER_KVDB_H

#include <any>
#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "expression.hpp"
#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Common builder for KVDB extract operations
 *
 * This builder is not intended to be used directly, i.e. it is not registered.
 * Exposed for testing purposes.
 *
 * @param definition
 * @param merge
 * @return base::Expression
 */
base::Expression KVDBExtract(const std::any& definition,
                             bool merge,
                             std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builder for KVDB set operation
 *
 * This builder is not intended to be used directly, i.e. it is not registered.
 * Exposed for testing purposes.
 *
 * @param definition
 * @return base::Expression
 */
base::Expression KVDBSet(const std::any& definition,
                         std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builds KVDB extract function helper
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBExtract(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builds KVDB extract and merge function helper
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder
getOpBuilderKVDBExtractMerge(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief get the KVDB match function helper builder
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBMatch(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Get the KVDB not-match function helper builder
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBNotMatch(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Get the KVDB Set function helper builder
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBSet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

} // namespace builder::internals::builders

// namespace builder::internals::builders

#endif // _OP_BUILDER_MAP_H

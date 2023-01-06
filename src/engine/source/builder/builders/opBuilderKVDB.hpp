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
 * @brief Common builder for KVDB get operations
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param definition
 * @param merge
 * @return base::Expression
 */
base::Expression
KVDBGet(const std::any& definition, bool merge, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builder for KVDB set operation
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param definition
 * @return base::Expression
 */
base::Expression KVDBSet(const std::any& definition, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builder for KVDB delete operation
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param definition
 * @return base::Expression
 */
base::Expression KVDBDelete(const std::any& definition, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builds KVDB extract function helper
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

/**
 * @brief Builds KVDB extract and merge function helper
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBGetMerge(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

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

/**
 * @brief Delete a KVDB function helper builder
 *
 * @param kvdbManager KVDB manager
 * @return Builder
 */
Builder getOpBuilderKVDBDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);


} // namespace builder::internals::builders

// namespace builder::internals::builders

#endif // _OP_BUILDER_MAP_H

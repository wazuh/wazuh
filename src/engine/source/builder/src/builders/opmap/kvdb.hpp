#ifndef _OP_BUILDER_KVDB_H
#define _OP_BUILDER_KVDB_H

#include <kvdb/ikvdbmanager.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

using namespace kvdbManager;

/**
 * @brief Common builder for KVDB get operations
 *
 * This builder is not intended to be used directly, i.e. it is not registered. It is exposed for testing purposes.
 *
 * @param targetField target field of the helper
 *
 * @param opArgs vector of parameters as present in the raw definition
 * @param merge
 * @return base::Expression
 */
TransformOp KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                    const std::string& kvdbScopeName,
                    const Reference& targetField,

                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx,
                    bool merge,
                    bool isRecursive = false);

/**
 * @brief Builds KVDB extract function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
TransformBuilder getOpBuilderKVDBGet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Builds KVDB extract and merge function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
TransformBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Builds KVDB extract and merge recursive function helper
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
TransformBuilder getOpBuilderKVDBGetMergeRecursive(std::shared_ptr<IKVDBManager> kvdbManager,
                                                   const std::string& kvdbScopeName);

/**
 * @brief get the KVDB match function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
FilterBuilder getOpBuilderKVDBMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Get the KVDB not-match function helper builder
 *
 * @param kvdbScope KVDB Scope
 * @return Builder
 */
FilterBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

/**
 * @brief Get the KVDB Get Array function helper builder
 *
 * @param kvdbManager KVDB Manager
 * @param kvdbScopeName KVDB Scope Name
 * @param schema Schema
 *
 * @return Builder
 */
TransformBuilder getOpBuilderKVDBGetArray(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

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
 *
 * @param opArgs vector of parameters as present in the raw definition.
 * @param buildCtx Build context
 * @param kvdbManager KVDB Manager
 * @param kvdbScopeName KVDB Scope Name
 * @param schema schema to validate fields
 * @return TransformOp The Lifter with the SHA1 hash.
 * @throw std::runtime_error if the parameter size is not one.
 */
TransformOp OpBuilderHelperKVDBDecodeBitmask(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx,
                                             std::shared_ptr<IKVDBManager> kvdbManager,
                                             const std::string& kvdbScopeName);

/**
 * @brief Get the 'kvdb_decode_bitmask' function helper builder
 *
 * @param kvdbManager KVDB Manager
 * @param kvdbScopeName KVDB Scope
 * @param schema schema to validate fields
 * @return TransformBuilder The builder of the helper.
 */
TransformBuilder getOpBuilderHelperKVDBDecodeBitmask(std::shared_ptr<IKVDBManager> kvdbManager,
                                                     const std::string& kvdbScopeName);

} // namespace builder::builders

// namespace builder::internals::builders

#endif // _OP_BUILDER_MAP_H

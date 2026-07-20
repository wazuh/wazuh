#ifndef _OP_BUILDER_KVDB_H
#define _OP_BUILDER_KVDB_H

#include <kvdbstore/ikvdbmanager.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

using namespace kvdbstore;

/**
 * @brief Common builder for KVDB get operations.
 *
 * This builder is not intended to be used directly, i.e. it is not registered.
 * It is exposed for testing purposes.
 *
 * @param kvdbManager KVDB manager instance.
 * @param targetField Target field of the helper.
 * @param opArgs Vector of parameters as present in the raw definition.
 * @param buildCtx Build context.
 * @param merge Whether the value should be merged into the target field.
 * @param isRecursive Whether the merge should be recursive.
 * @return TransformOp Built transform operation.
 */
TransformOp KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                    const Reference& targetField,
                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx,
                    bool merge,
                    bool isRecursive = false);

/**
 * @brief Builds KVDB extract function helper.
 *
 * @param kvdbManager KVDB manager instance.
 * @return Builder.
 */
TransformBuilder getOpBuilderKVDBGet(std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Builds KVDB extract and merge function helper.
 *
 * @param kvdbManager KVDB manager instance.
 * @return Builder.
 */
TransformBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Builds KVDB extract and merge recursive function helper.
 *
 * @param kvdbManager KVDB manager instance.
 * @return Builder.
 */
TransformBuilder getOpBuilderKVDBGetMergeRecursive(std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Get the KVDB match function helper builder.
 *
 * @param kvdbManager KVDB manager instance.
 * @return Builder.
 */
FilterBuilder getOpBuilderKVDBMatch(std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Get the KVDB not-match function helper builder.
 *
 * @param kvdbManager KVDB manager instance.
 * @return Builder.
 */
FilterBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Get the KVDB get-array function helper builder.
 *
 * @param kvdbManager KVDB manager instance.
 * @return Builder.
 */
TransformBuilder getOpBuilderKVDBGetArray(std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Builds helper BitmaskToTable, that maps a bitmask to a table of values.
 *
 * Usage: <field>: kvdb_decode_bitmask(KVDB_name, keyKVDB, $mask)
 *
 * The table should be an object with the following format:
 *   "bit position in decimal": JsonValue()
 * Example:
 * {
 *     "1": "value1",
 *     "2": "value2",
 *     "3": "value3",
 *     "4": "value4",
 *     ...
 *     "31": "value31",
 *     "32": "value32",
 *     ...
 *     "64": "value64"
 * }
 *
 * If the bit position is not set, it will be ignored.
 *
 * @param targetField Target field of the helper.
 * @param opArgs Vector of parameters as present in the raw definition.
 * @param buildCtx Build context.
 * @param kvdbManager KVDB manager instance.
 * @return TransformOp Built transform operation.
 * @throw std::runtime_error if the parameter size is not correct.
 */
TransformOp OpBuilderHelperKVDBDecodeBitmask(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx,
                                             std::shared_ptr<IKVDBManager> kvdbManager);

/**
 * @brief Get the 'kvdb_decode_bitmask' function helper builder.
 *
 * @param kvdbManager KVDB manager instance.
 * @return TransformBuilder The builder of the helper.
 */
TransformBuilder getOpBuilderHelperKVDBDecodeBitmask(std::shared_ptr<IKVDBManager> kvdbManager);
} // namespace builder::builders

#endif // _OP_BUILDER_KVDB_H

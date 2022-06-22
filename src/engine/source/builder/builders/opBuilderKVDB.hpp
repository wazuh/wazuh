#ifndef _OP_BUILDER_KVDB_H
#define _OP_BUILDER_KVDB_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds KVDB extract function helper
 *
 * @param definition
 * @return base::Expression
 */
base::Expression opBuilderKVDBExtract(const std::any definition);

/**
 * @brief Builds KVDB match function helper
 *
 * @param definition
 * @return base::Expression
 */
base::Expression opBuilderKVDBMatch(const std::any definition);

/**
 * @brief Builds KVDB not-match function helper
 *
 * @param definition
 * @return base::Expression
 */
base::Expression opBuilderKVDBNotMatch(const std::any definition);
} // namespace builder::internals::builders

// namespace builder::internals::builders

#endif // _OP_BUILDER_MAP_H

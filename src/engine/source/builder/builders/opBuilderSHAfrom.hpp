#ifndef _OP_BUILDER_SHA_FROM_H
#define _OP_BUILDER_SHA_FROM_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds helper SHA1 hash calculated from a strings or a set of strings
 * as parameters.
 * @param definition Definition of the operation to be built.
 * @return base::Expression The Lifter with the SHA1 hash.
 * @throw std::runtime_error if the parameter size is less than one.
 */
base::Expression opBuilderSHAfrom(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_SHA_FROM_H

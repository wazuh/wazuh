#ifndef _OP_BUILDER_FILE_OUTPUT_H
#define _OP_BUILDER_FILE_OUTPUT_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds file output operation.
 *
 * @param definition Definition of the operation to be built
 * @return base::Expression
 */
base::Expression opBuilderFileOutput(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_FILE_OUTPUT_H

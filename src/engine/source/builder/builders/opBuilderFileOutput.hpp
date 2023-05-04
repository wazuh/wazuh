#ifndef _OP_BUILDER_FILE_OUTPUT_H
#define _OP_BUILDER_FILE_OUTPUT_H

#include <any>

#include <defs/idefinitions.hpp>

#include "expression.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds file output operation.
 *
 * @param definition Definition of the operation to be built
 * @param definitions Definitions handler
 * @return base::Expression
 */
base::Expression opBuilderFileOutput(const std::any& definition, std::shared_ptr<defs::IDefinitions> definitions);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_FILE_OUTPUT_H

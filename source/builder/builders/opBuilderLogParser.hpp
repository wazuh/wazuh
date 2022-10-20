#ifndef _OP_BUILDER_LOG_PARSER_H
#define _OP_BUILDER_LOG_PARSER_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds parsing stage to be able to get information from the original
 * logged event
 *
 * @param definition Definition of the stage
 * @return base::Expression
 */
base::Expression opBuilderLogParser(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_LOG_PARSER_H

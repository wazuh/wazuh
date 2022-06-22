#ifndef _STAGE_BUILDER_PARSE_H
#define _STAGE_BUILDER_PARSE_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds parsing stage to be able to get information from the original
 * logged event
 *
 * @param definition JSON with the definition of the stage
 * @return base::Expression
 */
base::Expression stageBuilderParse(const std::any& definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_PARSE_H

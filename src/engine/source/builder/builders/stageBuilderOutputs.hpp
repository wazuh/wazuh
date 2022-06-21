#ifndef _STAGE_BUILDER_OUTPUTS_H
#define _STAGE_BUILDER_OUTPUTS_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds stage outputs
 *
 * @param definition
 * @return base::Expression
 */
base::Expression stageBuilderOutputs(const std::any& definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_OUTPUTS_H

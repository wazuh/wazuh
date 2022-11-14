#ifndef _STAGE_BUILDER_OUTPUTS_H
#define _STAGE_BUILDER_OUTPUTS_H

#include <any>
#include <memory>

#include <expression.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the builder that builds stage outputs
 *
 * @param registry Registry of builders.
 * @return Builder
 */
Builder getStageBuilderOutputs(std::shared_ptr<Registry> registry);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_OUTPUTS_H

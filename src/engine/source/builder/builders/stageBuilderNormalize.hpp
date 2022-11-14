#ifndef _STAGE_BUILDER_NORMALIZE_H
#define _STAGE_BUILDER_NORMALIZE_H

#include <any>
#include <memory>

#include <expression.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the Stage Normalize Builder
 *
 * @param registry Registry of builders.
 * @return Builder
 */
Builder getStageNormalizeBuilder(std::shared_ptr<Registry> registry);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_NORMALIZE_H

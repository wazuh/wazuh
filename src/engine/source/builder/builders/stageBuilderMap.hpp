
#ifndef _STAGE_BUILDER_MAP_H
#define _STAGE_BUILDER_MAP_H

#include <any>
#include <memory>

#include <expression.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the Stage Map Builder
 *
 * @param registry Registry of builders.
 * @return Builder
 */
Builder getStageMapBuilder(std::shared_ptr<Registry> registry);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_MAP_H

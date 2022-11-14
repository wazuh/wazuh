#ifndef _STAGE_BUILDER_CHECK_H
#define _STAGE_BUILDER_CHECK_H

#include <any>
#include <memory>

#include <expression.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the Stage Builder Check
 *
 * @param registry Registry of builders.
 * @return Builder
 */
Builder getStageBuilderCheck(std::shared_ptr<Registry> registry);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_CHECK_H

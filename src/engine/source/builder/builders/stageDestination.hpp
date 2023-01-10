#ifndef _BUILDER_BUILDERS_STAGEDESTINATION_HPP
#define _BUILDER_BUILDERS_STAGEDESTINATION_HPP

#include <any>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the Stage destination builder
 *
 * @param registry Registry of builders.
 * @return Builder
 */
Builder getStageDestinationBuilder(std::shared_ptr<Registry> registry);

} // namespace builder::internals::builders

#endif

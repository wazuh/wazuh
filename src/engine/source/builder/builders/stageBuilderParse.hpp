#ifndef _STAGE_BUILDER_PARSE_H
#define _STAGE_BUILDER_PARSE_H

#include <any>
#include <memory>

#include <expression.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Return the builder that builds parsing stage to be able to get information from
 * the original logged event
 *
 * @param registry Registry of builders.
 * @return Builder
 */
Builder getStageBuilderParse(std::shared_ptr<Registry> registry);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_PARSE_H

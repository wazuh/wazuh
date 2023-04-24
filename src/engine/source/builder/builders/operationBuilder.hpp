#ifndef _OPERATION_BUILDER_H
#define _OPERATION_BUILDER_H

#include <any>
#include <memory>

#include <expression.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the Operation Condition Builder
 *
 * @param helperRegistry Registry of helper builders.
 * @return Builder
 */
Builder getOperationConditionBuilder(std::shared_ptr<Registry<HelperBuilder>> helperRegistry);

/**
 * @brief Get the Operation Map Builder
 *
 * @param helperRegistry Registry of helper builders.
 * @return Builder
 */
Builder getOperationMapBuilder(std::shared_ptr<Registry<HelperBuilder>> helperRegistry);

} // namespace builder::internals::builders

#endif // _OPERATION_BUILDER_H

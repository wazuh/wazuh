#ifndef _OPERATION_BUILDER_H
#define _OPERATION_BUILDER_H

#include <any>
#include <memory>

#include <expression.hpp>
#include <schemf/ischema.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Get the Operation Condition Builder
 *
 * @param helperRegistry Registry of helper builders.
 * @return Builder
 */
Builder getOperationConditionBuilder(std::shared_ptr<Registry<HelperBuilder>> helperRegistry,
                                     std::shared_ptr<schemf::ISchema> schema, bool forceFieldNaming = false);

/**
 * @brief Get the Operation Map Builder
 *
 * @param helperRegistry Registry of helper builders.
 * @return Builder
 */
Builder getOperationMapBuilder(std::shared_ptr<Registry<HelperBuilder>> helperRegistry,
                               std::shared_ptr<schemf::ISchema> schema, bool forceFieldNaming = false);

} // namespace builder::internals::builders

#endif // _OPERATION_BUILDER_H

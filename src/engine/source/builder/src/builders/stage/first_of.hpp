#ifndef _BUILDER_STAGE_FIRST_OF_HPP
#define _BUILDER_STAGE_FIRST_OF_HPP

#include <base/expression.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Build a first_of stage expression
 *
 * The first_of stage evaluates an ordered list of check-then items.
 * It executes the "then" action of the first item whose "check" succeeds,
 * then stops evaluation (short-circuit behavior).
 *
 * Expected JSON format:
 * [
 *   {"check": <check-definition>, "then": <output-definition>},
 *   {"check": <check-definition>, "then": <output-definition>}
 * ]
 *
 * @param definition JSON array of item objects
 * @param buildCtx Build context with registry access
 * @return base::Expression Or operation containing Implication items
 * @throw std::runtime_error if validation fails or array is empty
 */
base::Expression firstOfBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _BUILDER_STAGE_FIRST_OF_HPP

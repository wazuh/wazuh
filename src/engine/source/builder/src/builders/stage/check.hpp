#ifndef _BUILDER_BUILDERS_STAGE_CHECK_HPP
#define _BUILDER_BUILDERS_STAGE_CHECK_HPP

#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Build the check stage expression.
 *
 * @param definition Json definition of the stage.
 * @param buildCtx Build context.
 * @return base::Expression The built stage expression.
 */
base::Expression checkBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_CHECK_HPP

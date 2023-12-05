#ifndef _BUILDER_BUILDERS_STAGE_NORMALIZE_HPP
#define _BUILDER_BUILDERS_STAGE_NORMALIZE_HPP

#include "builders/types.hpp"

namespace builder::builders
{

base::Expression normalizeBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_NORMALIZE_HPP

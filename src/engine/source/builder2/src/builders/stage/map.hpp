
#ifndef _BUILDER_BUILDERS_STAGE_MAP_HPP
#define _BUILDER_BUILDERS_STAGE_MAP_HPP

#include "builders/types.hpp"

namespace builder::builders
{

base::Expression mapBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_MAP_HPP

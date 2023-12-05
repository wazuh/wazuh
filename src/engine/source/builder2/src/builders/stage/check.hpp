#ifndef _BUILDER_BUILDERS_STAGE_CHECK_HPP
#define _BUILDER_BUILDERS_STAGE_CHECK_HPP

#include "builders/types.hpp"

namespace builder::builders
{

base::Expression checkBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_CHECK_HPP

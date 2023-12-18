#ifndef _BUILDER_BUILDERS_OPMAP_MAP_HPP
#define _BUILDER_BUILDERS_OPMAP_MAP_HPP

#include "builders/types.hpp"

namespace builder::builders::opmap
{
MapOp mapBuilder(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

DynamicValToken mapValidator();
} // namespace builder::builders::opmap

#endif // _BUILDER_BUILDERS_OPMAP_MAP_HPP

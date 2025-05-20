#ifndef _BUILDER_BUILDERS_OPFILTER_FILTER_HPP
#define _BUILDER_BUILDERS_OPFILTER_FILTER_HPP

#include "builders/types.hpp"

namespace builder::builders::opfilter
{
FilterOp filterBuilder(const Reference& targetField,
                       const std::vector<OpArg>& opArgs,
                       const std::shared_ptr<const IBuildCtx>& buildCtx);

DynamicValToken filterValidator();
} // namespace builder::builders::opfilter

#endif // _BUILDER_BUILDERS_OPFILTER_FILTER_HPP

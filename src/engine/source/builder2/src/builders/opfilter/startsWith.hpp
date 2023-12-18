#ifndef _BUILDER_BUILDERS_OPFILTER_STARTSWITH_HPP
#define _BUILDER_BUILDERS_OPFILTER_STARTSWITH_HPP

#include "builders/types.hpp"

namespace builder::builders::opfilter
{
FilterOp startsWithBuilder(const Reference& targetField,
                           const std::vector<OpArg>& opArgs,
                           const std::shared_ptr<const IBuildCtx>& buildCtx);
} // namespace builder::builders::opfilter

#endif // _BUILDER_BUILDERS_OPFILTER_STARTSWITH_HPP

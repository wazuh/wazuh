#ifndef _BUILDER_BUILDERS_OPFILTER_EXISTS_HPP
#define _BUILDER_BUILDERS_OPFILTER_EXISTS_HPP

#include "builders/types.hpp"

namespace builder::builders::opfilter
{
FilterOp existsBuilder(const Reference& targetField,
                       const std::vector<OpArg>& opArgs,
                       const std::shared_ptr<const IBuildCtx>& buildCtx);

FilterOp notExistsBuilder(const Reference& targetField,
                          const std::vector<OpArg>& opArgs,
                          const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders::opfilter

#endif // _BUILDER_BUILDERS_OPFILTER_EXISTS_HPP

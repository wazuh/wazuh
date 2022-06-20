#ifndef _STAGE_BUILDER_NORMALIZE_H
#define _STAGE_BUILDER_NORMALIZE_H

#include <any>

#include "builder/expression.hpp"

namespace builder::internals::builders
{

Expression stageNormalizeBuilder(std::any definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_NORMALIZE_H

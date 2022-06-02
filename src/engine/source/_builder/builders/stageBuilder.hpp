#ifndef _STAGE_BUILDER_H
#define _STAGE_BUILDER_H

#include <any>

#include "_builder/expression.hpp"

namespace builder::internals::builders
{

Expression stageCheckBuilder(std::any definition);

Expression stageMapBuilder(std::any definition);

Expression stageNormalizeBuilder(std::any definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_H

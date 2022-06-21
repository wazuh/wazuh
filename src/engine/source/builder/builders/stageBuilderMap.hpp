
#ifndef _STAGE_BUILDER_MAP_H
#define _STAGE_BUILDER_MAP_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

base::Expression stageMapBuilder(std::any definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_MAP_H

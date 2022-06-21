#ifndef _STAGE_BUILDER_NORMALIZE_H
#define _STAGE_BUILDER_NORMALIZE_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

base::Expression stageNormalizeBuilder(const std::any& definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_NORMALIZE_H

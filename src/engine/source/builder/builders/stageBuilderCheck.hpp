#ifndef _STAGE_BUILDER_CHECK_H
#define _STAGE_BUILDER_CHECK_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

base::Expression stageBuilderCheck(std::any definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_CHECK_H

#ifndef _STAGE_BUILDER_CHECK_H
#define _STAGE_BUILDER_CHECK_H

#include <any>

#include "builder/expression.hpp"

namespace builder::internals::builders
{

Expression stageCheckBuilder(std::any definition);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_CHECK_H

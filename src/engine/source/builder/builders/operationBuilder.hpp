#ifndef _OPERATION_BUILDER_H
#define _OPERATION_BUILDER_H

#include <any>

#include "builder/expression.hpp"

namespace builder::internals::builders
{

Expression operationConditionBuilder(std::any definition);

Expression operationMapBuilder(std::any definition);

} // namespace builder::internals::builders

#endif // _OPERATION_BUILDER_H

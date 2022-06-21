#ifndef _OPERATION_BUILDER_H
#define _OPERATION_BUILDER_H

#include <any>

#include "expression.hpp"

namespace builder::internals::builders
{

base::Expression operationConditionBuilder(std::any definition);

base::Expression operationMapBuilder(std::any definition);

} // namespace builder::internals::builders

#endif // _OPERATION_BUILDER_H

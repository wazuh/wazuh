#ifndef _REGISTER_H
#define _REGISTER_H

#include "builder/builders/operationBuilder.hpp"
#include "builder/builders/stageBuilderCheck.hpp"
#include "builder/builders/stageBuilderMap.hpp"
#include "builder/builders/stageBuilderNormalize.hpp"
#include "builder/registry.hpp"

namespace builder::internals
{
static void registerBuilders()
{
    Registry::registerBuilder(builders::operationMapBuilder, "operation.map");
    Registry::registerBuilder(builders::operationConditionBuilder, "operation.condition");
    Registry::registerBuilder(builders::stageCheckBuilder, "stage.check");
    Registry::registerBuilder(builders::stageMapBuilder, "stage.map");
    Registry::registerBuilder(builders::stageNormalizeBuilder, "stage.normalize");
}
} // namespace builder::internals

#endif // _REGISTER_H

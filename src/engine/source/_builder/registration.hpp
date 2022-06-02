#ifndef _REGISTRATION_H
#define _REGISTRATION_H

#include "_builder/builders/operationBuilder.hpp"
#include "_builder/builders/stageBuilder.hpp"
#include "_builder/registry.hpp"

namespace builder::internals
{
static void registerBuilders()
{
    Registry::registerBuilder(builders::operationMapBuilder, "operation.map");
    Registry::registerBuilder(builders::operationConditionBuilder,
                              "operation.condition");
    Registry::registerBuilder(builders::stageCheckBuilder, "stage.check");
    Registry::registerBuilder(builders::stageMapBuilder, "stage.map");
    Registry::registerBuilder(builders::stageNormalizeBuilder,
                              "stage.normalize");
}
} // namespace builder::internals

#endif // _REGISTRATION_H

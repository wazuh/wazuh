#ifndef _REGISTER_H
#define _REGISTER_H

#include "builders/operationBuilder.hpp"
#include "builders/stageBuilderCheck.hpp"
#include "builders/stageBuilderMap.hpp"
#include "builders/stageBuilderNormalize.hpp"
#include "builders/opBuilderFileOutput.hpp"
#include "builders/stageBuilderOutputs.hpp"
#include "registry.hpp"

namespace builder::internals
{
static void registerBuilders()
{
    Registry::registerBuilder(builders::operationMapBuilder, "operation.map");
    Registry::registerBuilder(builders::operationConditionBuilder, "operation.condition");

    Registry::registerBuilder(builders::stageCheckBuilder, "stage.check", "stage.allow");
    Registry::registerBuilder(builders::stageMapBuilder, "stage.map");
    Registry::registerBuilder(builders::stageNormalizeBuilder, "stage.normalize");

    Registry::registerBuilder(builders::stageBuilderOutputs, "stage.outputs");
    Registry::registerBuilder(builders::opBuilderFileOutput, "output.file");

}
} // namespace builder::internals

#endif // _REGISTER_H

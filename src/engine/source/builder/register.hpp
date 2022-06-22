#ifndef _REGISTER_H
#define _REGISTER_H

#include "builders/opBuilderFileOutput.hpp"
#include "builders/operationBuilder.hpp"
#include "builders/stageBuilderCheck.hpp"
#include "builders/stageBuilderMap.hpp"
#include "builders/stageBuilderNormalize.hpp"
#include "builders/stageBuilderOutputs.hpp"
#include "builders/stageBuilderParse.hpp"
#include "builders/opBuilderLogqlParser.hpp"
#include "builders/opBuilderKVDB.hpp"
#include "builders/opBuilderHelperFilter.hpp"
#include "registry.hpp"

namespace builder::internals
{
static void registerBuilders()
{
    // Basic operations
    Registry::registerBuilder(builders::operationMapBuilder, "operation.map");
    Registry::registerBuilder(builders::operationConditionBuilder, "operation.condition");

    // Stages
    Registry::registerBuilder(builders::stageCheckBuilder, "stage.check", "stage.allow");
    Registry::registerBuilder(builders::stageMapBuilder, "stage.map");
    Registry::registerBuilder(builders::stageNormalizeBuilder, "stage.normalize");

    // Parsers
    Registry::registerBuilder(builders::stageBuilderParse, "stage.parse");
    Registry::registerBuilder(builders::opBuilderLogqlParser, "parser.logql");

    // Outputs
    Registry::registerBuilder(builders::stageBuilderOutputs, "stage.outputs");
    Registry::registerBuilder(builders::opBuilderFileOutput, "output.file");

    // KVDB
    Registry::registerBuilder(builders::opBuilderKVDBExtract, "helper.kvdb_extract");
    Registry::registerBuilder(builders::opBuilderKVDBMatch, "helper.kvdb_match");
    Registry::registerBuilder(builders::opBuilderKVDBNotMatch, "helper.kvdb_not_match");

    // Filter Helpers
    Registry::registerBuilder(builders::opBuilderHelperExists, "helper.exists");
}
} // namespace builder::internals

#endif // _REGISTER_H

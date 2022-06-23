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
#include "builders/opBuilderHelperMap.hpp"
#include "registry.hpp"

namespace builder::internals
{
static void registerBuilders()
{
    // Basic operations
    Registry::registerBuilder(builders::operationMapBuilder, "operation.map");
    Registry::registerBuilder(builders::operationConditionBuilder, "operation.condition");

    // Stages
    Registry::registerBuilder(builders::stageBuilderCheck, "stage.check", "stage.allow");
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
    Registry::registerBuilder(builders::opBuilderHelperNotExists, "helper.not_exists");
    Registry::registerBuilder(builders::opBuilderHelperIntEqual, "helper.i_eq");
    Registry::registerBuilder(builders::opBuilderHelperIntNotEqual, "helper.i_ne");
    Registry::registerBuilder(builders::opBuilderHelperIntGreaterThan, "helper.i_gt");
    Registry::registerBuilder(builders::opBuilderHelperIntGreaterThanEqual, "helper.i_ge");
    Registry::registerBuilder(builders::opBuilderHelperIntLessThan, "helper.i_lt");
    Registry::registerBuilder(builders::opBuilderHelperIntLessThanEqual, "helper.i_le");
    Registry::registerBuilder(builders::opBuilderHelperStringEQ, "helper.s_eq");
    Registry::registerBuilder(builders::opBuilderHelperStringNE, "helper.s_ne");
    Registry::registerBuilder(builders::opBuilderHelperStringGT, "helper.s_gt");
    Registry::registerBuilder(builders::opBuilderHelperStringGE, "helper.s_ge");
    Registry::registerBuilder(builders::opBuilderHelperStringLT, "helper.s_lt");
    Registry::registerBuilder(builders::opBuilderHelperStringLE, "helper.s_le");
    Registry::registerBuilder(builders::opBuilderHelperRegexMatch, "helper.r_match");
    Registry::registerBuilder(builders::opBuilderHelperRegexNotMatch, "helper.r_not_match");
    Registry::registerBuilder(builders::opBuilderHelperIPCIDR, "helper.ip_cidr");

    // Map Helpers
    Registry::registerBuilder(builders::opBuilderHelperIntCalc, "helper.i_calc");
    Registry::registerBuilder(builders::opBuilderHelperStringUP, "helper.s_up");
    Registry::registerBuilder(builders::opBuilderHelperStringLO, "helper.s_lo");
    Registry::registerBuilder(builders::opBuilderHelperStringTrim, "helper.s_trim");
    Registry::registerBuilder(builders::opBuilderHelperRegexExtract, "helper.r_ext");

}
} // namespace builder::internals

#endif // _REGISTER_H

#ifndef _REGISTER_H
#define _REGISTER_H

#include "builders/opBuilderARWrite.hpp"
#include "builders/opBuilderFileOutput.hpp"
#include "builders/opBuilderHelperHashSHA1.hpp"
#include "builders/opBuilderHelperFilter.hpp"
#include "builders/opBuilderHelperMap.hpp"
#include "builders/opBuilderHelperNetInfoAddress.hpp"
#include "builders/opBuilderKVDB.hpp"
#include "builders/opBuilderLogqlParser.hpp"
#include "builders/opBuilderSCAdecoder.hpp"
#include "builders/opBuilderWdb.hpp"
#include "builders/operationBuilder.hpp"
#include "builders/stageBuilderCheck.hpp"
#include "builders/stageBuilderMap.hpp"
#include "builders/stageBuilderNormalize.hpp"
#include "builders/stageBuilderOutputs.hpp"
#include "builders/stageBuilderParse.hpp"
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
    Registry::registerBuilder(builders::opBuilderHelperIntGreaterThanEqual,
                              "helper.i_ge");
    Registry::registerBuilder(builders::opBuilderHelperIntLessThan, "helper.i_lt");
    Registry::registerBuilder(builders::opBuilderHelperIntLessThanEqual, "helper.i_le");
    Registry::registerBuilder(builders::opBuilderHelperStringEqual, "helper.s_eq");
    Registry::registerBuilder(builders::opBuilderHelperStringNotEqual, "helper.s_ne");
    Registry::registerBuilder(builders::opBuilderHelperStringGreaterThan, "helper.s_gt");
    Registry::registerBuilder(builders::opBuilderHelperStringGreaterThanEqual,
                              "helper.s_ge");
    Registry::registerBuilder(builders::opBuilderHelperStringLessThan, "helper.s_lt");
    Registry::registerBuilder(builders::opBuilderHelperStringLessThanEqual,
                              "helper.s_le");
    Registry::registerBuilder(builders::opBuilderHelperRegexMatch, "helper.r_match");
    Registry::registerBuilder(builders::opBuilderHelperRegexNotMatch,
                              "helper.r_not_match");
    Registry::registerBuilder(builders::opBuilderHelperIPCIDR, "helper.ip_cidr");
    Registry::registerBuilder(builders::opBuilderHelperContainsString,
                              "helper.s_contains");
    Registry::registerBuilder(builders::opBuilderHelperDeleteField,
                              "helper.delete_field");
    Registry::registerBuilder(builders::opBuilderHelperContainsString,
                              "helper.s_starts");
    Registry::registerBuilder(builders::opBuilderHelperIsNumber, "helper.is_number");
    Registry::registerBuilder(builders::opBuilderHelperIsNotNumber,
                              "helper.is_not_number");
    Registry::registerBuilder(builders::opBuilderHelperIsString, "helper.is_string");
    Registry::registerBuilder(builders::opBuilderHelperIsNotString,
                              "helper.is_not_string");
    Registry::registerBuilder(builders::opBuilderHelperIsBool, "helper.is_bool");
    Registry::registerBuilder(builders::opBuilderHelperIsNotBool, "helper.is_not_bool");
    Registry::registerBuilder(builders::opBuilderHelperIsArray, "helper.is_array");
    Registry::registerBuilder(builders::opBuilderHelperIsNotArray, "helper.is_not_array");
    Registry::registerBuilder(builders::opBuilderHelperIsObject, "helper.is_object");
    Registry::registerBuilder(builders::opBuilderHelperIsNotObject,
                              "helper.is_not_object");
    Registry::registerBuilder(builders::opBuilderHelperIsNull, "helper.is_null");
    Registry::registerBuilder(builders::opBuilderHelperIsNotNull, "helper.is_not_null");
    Registry::registerBuilder(builders::opBuilderHelperIsTrue, "helper.is_true");
    Registry::registerBuilder(builders::opBuilderHelperIsFalse, "helper.is_false");

    // Map Helpers
    Registry::registerBuilder(builders::opBuilderHelperIntCalc, "helper.i_calc");
    Registry::registerBuilder(builders::opBuilderHelperStringUP, "helper.s_up");
    Registry::registerBuilder(builders::opBuilderHelperStringLO, "helper.s_lo");
    Registry::registerBuilder(builders::opBuilderHelperStringTrim, "helper.s_trim");
    Registry::registerBuilder(builders::opBuilderHelperStringConcat, "helper.s_concat");
    Registry::registerBuilder(builders::opBuilderHelperStringFromArray,
                              "helper.s_fromArray");
    Registry::registerBuilder(builders::opBuilderHelperRegexExtract, "helper.r_ext");
    Registry::registerBuilder(builders::opBuilderHelperAppendString, "helper.s_append");
    Registry::registerBuilder(builders::opBuilderHelperAppendSplitString, "helper.s_to_array");

    // DB sync
    Registry::registerBuilder(builders::opBuilderWdbQuery, "helper.wdb_query");
    Registry::registerBuilder(builders::opBuilderWdbUpdate, "helper.wdb_update");
    Registry::registerBuilder(builders::opBuilderARWrite, "helper.ar_write");

    // SCA decoder
    Registry::registerBuilder(builders::opBuilderSCAdecoder, "helper.sca_decoder");

    //SysCollector - netInfo
    Registry::registerBuilder(builders::opBuilderHelperSaveNetInfoIPv4,
                              "helper.saveNetInfoIPv4");
    Registry::registerBuilder(builders::opBuilderHelperSaveNetInfoIPv6,
                              "helper.saveNetInfoIPv6");

    // SHA1
    Registry::registerBuilder(builders::opBuilderHelperHashSHA1, "helper.hash_sha1");

}
} // namespace builder::internals

#endif // _REGISTER_H

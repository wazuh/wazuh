#ifndef _REGISTER_H
#define _REGISTER_H

#include "builders/opBuilderFileOutput.hpp"
#include "builders/opBuilderHelperActiveResponse.hpp"
#include "builders/opBuilderHelperFilter.hpp"
#include "builders/opBuilderHelperMap.hpp"
#include "builders/opBuilderHelperNetInfoAddress.hpp"
#include "builders/opBuilderKVDB.hpp"
#include "builders/opBuilderLogParser.hpp"
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
    Registry::registerBuilder(builders::opBuilderLogParser, "parser.logpar");

    // Outputs
    Registry::registerBuilder(builders::stageBuilderOutputs, "stage.outputs");
    Registry::registerBuilder(builders::opBuilderFileOutput, "output.file");

    // Filter Helpers
    Registry::registerBuilder(builders::opBuilderHelperContainsString,
                              "helper.a_contains");
    Registry::registerBuilder(builders::opBuilderHelperIntEqual, "helper.i_eq");
    Registry::registerBuilder(builders::opBuilderHelperIntGreaterThan, "helper.i_gt");
    Registry::registerBuilder(builders::opBuilderHelperIntGreaterThanEqual,
                              "helper.i_ge");
    Registry::registerBuilder(builders::opBuilderHelperIntLessThan, "helper.i_lt");
    Registry::registerBuilder(builders::opBuilderHelperIntLessThanEqual, "helper.i_le");
    Registry::registerBuilder(builders::opBuilderHelperIntNotEqual, "helper.i_ne");
    Registry::registerBuilder(builders::opBuilderHelperIPCIDR, "helper.ip_cidr");
    Registry::registerBuilder(builders::opBuilderHelperIsArray, "helper.t_is_array");
    Registry::registerBuilder(builders::opBuilderHelperIsBool, "helper.t_is_bool");
    Registry::registerBuilder(builders::opBuilderHelperIsFalse, "helper.t_is_false");
    Registry::registerBuilder(builders::opBuilderHelperIsNotArray,
                              "helper.t_is_not_array");
    Registry::registerBuilder(builders::opBuilderHelperIsNotBool, "helper.t_is_not_bool");
    Registry::registerBuilder(builders::opBuilderHelperIsNotNull, "helper.t_is_not_null");
    Registry::registerBuilder(builders::opBuilderHelperIsNotNumber,
                              "helper.t_is_not_num");
    Registry::registerBuilder(builders::opBuilderHelperIsNotObject,
                              "helper.t_is_not_object");
    Registry::registerBuilder(builders::opBuilderHelperIsNotString,
                              "helper.t_is_not_string");
    Registry::registerBuilder(builders::opBuilderHelperIsNull, "helper.t_is_null");
    Registry::registerBuilder(builders::opBuilderHelperIsNumber, "helper.t_is_num");
    Registry::registerBuilder(builders::opBuilderHelperIsObject, "helper.t_is_object");
    Registry::registerBuilder(builders::opBuilderHelperIsString, "helper.t_is_string");
    Registry::registerBuilder(builders::opBuilderHelperIsTrue, "helper.t_is_true");
    Registry::registerBuilder(builders::opBuilderHelperRegexMatch, "helper.r_match");
    Registry::registerBuilder(builders::opBuilderHelperRegexNotMatch,
                              "helper.r_not_match");
    Registry::registerBuilder(builders::opBuilderHelperStringEqual, "helper.s_eq");
    Registry::registerBuilder(builders::opBuilderHelperStringGreaterThan, "helper.s_gt");
    Registry::registerBuilder(builders::opBuilderHelperStringGreaterThanEqual,
                              "helper.s_ge");
    Registry::registerBuilder(builders::opBuilderHelperStringLessThan, "helper.s_lt");
    Registry::registerBuilder(builders::opBuilderHelperStringLessThanEqual,
                              "helper.s_le");
    Registry::registerBuilder(builders::opBuilderHelperStringNotEqual, "helper.s_ne");
    Registry::registerBuilder(builders::opBuilderHelperStringStarts, "helper.s_starts");
    // Filter helpers: Event Field functions
    Registry::registerBuilder(builders::opBuilderHelperExists, "helper.ef_exists");
    Registry::registerBuilder(builders::opBuilderHelperNotExists, "helper.ef_not_exists");

    // Map Helpers
    Registry::registerBuilder(builders::opBuilderHelperIntCalc, "helper.i_calc");
    Registry::registerBuilder(builders::opBuilderHelperRegexExtract, "helper.r_ext");
    // Map helpers: Event Field functions
    Registry::registerBuilder(builders::opBuilderHelperDeleteField, "helper.ef_delete");
    Registry::registerBuilder(builders::opBuilderHelperMerge, "helper.ef_merge");
    Registry::registerBuilder(builders::opBuilderHelperRenameField, "helper.ef_rename");
    // Map helpers: Hash functions
    Registry::registerBuilder(builders::opBuilderHelperHashSHA1, "helper.h_sha1");
    // Map helpers: String functions
    Registry::registerBuilder(builders::opBuilderHelperAppendSplitString,
                              "helper.s_to_array");
    Registry::registerBuilder(builders::opBuilderHelperAppend, "helper.a_append");
    Registry::registerBuilder(builders::opBuilderHelperHexToNumber,
                              "helper.s_hex_to_num");
    Registry::registerBuilder(builders::opBuilderHelperIPVersionFromIPStr,
                              "helper.s_ip_version");
    Registry::registerBuilder(builders::opBuilderHelperStringConcat, "helper.s_concat");
    Registry::registerBuilder(builders::opBuilderHelperStringFromArray,
                              "helper.s_from_array");
    Registry::registerBuilder(builders::opBuilderHelperStringFromHexa,
                              "helper.s_from_hexa");
    Registry::registerBuilder(builders::opBuilderHelperStringLO, "helper.s_lo");
    Registry::registerBuilder(builders::opBuilderHelperStringReplace, "helper.s_replace");
    Registry::registerBuilder(builders::opBuilderHelperStringTrim, "helper.s_trim");
    Registry::registerBuilder(builders::opBuilderHelperStringUP, "helper.s_up");
    // Map helpers: Time functions
    Registry::registerBuilder(builders::opBuilderHelperEpochTimeFromSystem,
                              "helper. sys_epoch");

    // Special helpers

    // Active Response
    Registry::registerBuilder(builders::opBuilderHelperCreateAR, "helper.ar_create");
    Registry::registerBuilder(builders::opBuilderHelperSendAR, "helper.ar_send");

    // DB sync
    Registry::registerBuilder(builders::opBuilderWdbQuery, "helper.wdb_query");
    Registry::registerBuilder(builders::opBuilderWdbUpdate, "helper.wdb_update");

    // KVDB
    Registry::registerBuilder(builders::opBuilderKVDBExtract, "helper.kvdb_get");
    Registry::registerBuilder(builders::opBuilderKVDBExtractMerge,
                              "helper.kvdb_get_merge");
    Registry::registerBuilder(builders::opBuilderKVDBMatch, "helper.kvdb_match");
    Registry::registerBuilder(builders::opBuilderKVDBNotMatch, "helper.kvdb_not_match");

    // SCA decoder
    Registry::registerBuilder(builders::opBuilderSCAdecoder, "helper.sca_decoder");

    // SysCollector - netInfo
    Registry::registerBuilder(builders::opBuilderHelperSaveNetInfoIPv4,
                              "helper.sysc_ni_save_ipv4");
    Registry::registerBuilder(builders::opBuilderHelperSaveNetInfoIPv6,
                              "helper.sysc_ni_save_ipv6");
}
} // namespace builder::internals

#endif // _REGISTER_H

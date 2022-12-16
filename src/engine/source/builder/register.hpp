#ifndef _REGISTER_H
#define _REGISTER_H

#include <hlp/logpar.hpp>
#include <kvdb/kvdbManager.hpp>

#include "builders/opBuilderFileOutput.hpp"
#include "builders/opBuilderHelperActiveResponse.hpp"
#include "builders/opBuilderHelperFilter.hpp"
#include "builders/opBuilderHelperMap.hpp"
#include "builders/opBuilderHelperNetInfoAddress.hpp"
#include "builders/opBuilderKVDB.hpp"
#include "builders/opBuilderLogParser.hpp"
#include "builders/opBuilderSCAdecoder.hpp"
#include "builders/opBuilderSpeficHLP.hpp"
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
struct dependencies
{
    std::shared_ptr<KVDBManager> kvdbManager;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    size_t logparDebugLvl;
};

static void registerBuilders(std::shared_ptr<Registry> registry,
                             const dependencies& dependencies = {})
{
    // Basic operations
    registry->registerBuilder(builders::getOperationMapBuilder(registry),
                              "operation.map");
    registry->registerBuilder(builders::getOperationConditionBuilder(registry),
                              "operation.condition");

    // Stages
    registry->registerBuilder(
        builders::getStageBuilderCheck(registry), "stage.check", "stage.allow");
    registry->registerBuilder(builders::getStageMapBuilder(registry), "stage.map");
    registry->registerBuilder(builders::getStageNormalizeBuilder(registry),
                              "stage.normalize");

    // Parsers
    registry->registerBuilder(builders::getStageBuilderParse(registry), "stage.parse");
    registry->registerBuilder(
        builders::getOpBuilderLogParser(dependencies.logpar, dependencies.logparDebugLvl),
        "parser.logpar");

    // Outputs
    registry->registerBuilder(builders::getStageBuilderOutputs(registry),
                              "stage.outputs");
    registry->registerBuilder(builders::opBuilderFileOutput, "output.file");

    // Filter Helpers
    registry->registerBuilder(builders::opBuilderHelperContainsString,
                              "helper.a_contains");
    registry->registerBuilder(builders::opBuilderHelperIntEqual, "helper.i_eq");
    registry->registerBuilder(builders::opBuilderHelperIntGreaterThan, "helper.i_gt");
    registry->registerBuilder(builders::opBuilderHelperIntGreaterThanEqual,
                              "helper.i_ge");
    registry->registerBuilder(builders::opBuilderHelperIntLessThan, "helper.i_lt");
    registry->registerBuilder(builders::opBuilderHelperIntLessThanEqual, "helper.i_le");
    registry->registerBuilder(builders::opBuilderHelperIntNotEqual, "helper.i_ne");
    registry->registerBuilder(builders::opBuilderHelperIPCIDR, "helper.ip_cidr");
    registry->registerBuilder(builders::opBuilderHelperIsArray, "helper.t_is_array");
    registry->registerBuilder(builders::opBuilderHelperIsBool, "helper.t_is_bool");
    registry->registerBuilder(builders::opBuilderHelperIsFalse, "helper.t_is_false");
    registry->registerBuilder(builders::opBuilderHelperIsNotArray,
                              "helper.t_is_not_array");
    registry->registerBuilder(builders::opBuilderHelperIsNotBool, "helper.t_is_not_bool");
    registry->registerBuilder(builders::opBuilderHelperIsNotNull, "helper.t_is_not_null");
    registry->registerBuilder(builders::opBuilderHelperIsNotNumber,
                              "helper.t_is_not_num");
    registry->registerBuilder(builders::opBuilderHelperIsNotObject,
                              "helper.t_is_not_object");
    registry->registerBuilder(builders::opBuilderHelperIsNotString,
                              "helper.t_is_not_string");
    registry->registerBuilder(builders::opBuilderHelperIsNull, "helper.t_is_null");
    registry->registerBuilder(builders::opBuilderHelperIsNumber, "helper.t_is_num");
    registry->registerBuilder(builders::opBuilderHelperIsObject, "helper.t_is_object");
    registry->registerBuilder(builders::opBuilderHelperIsString, "helper.t_is_string");
    registry->registerBuilder(builders::opBuilderHelperIsTrue, "helper.t_is_true");
    registry->registerBuilder(builders::opBuilderHelperRegexMatch, "helper.r_match");
    registry->registerBuilder(builders::opBuilderHelperRegexNotMatch,
                              "helper.r_not_match");
    registry->registerBuilder(builders::opBuilderHelperStringEqual, "helper.s_eq");
    registry->registerBuilder(builders::opBuilderHelperStringGreaterThan, "helper.s_gt");
    registry->registerBuilder(builders::opBuilderHelperStringGreaterThanEqual,
                              "helper.s_ge");
    registry->registerBuilder(builders::opBuilderHelperStringLessThan, "helper.s_lt");
    registry->registerBuilder(builders::opBuilderHelperStringLessThanEqual,
                              "helper.s_le");
    registry->registerBuilder(builders::opBuilderHelperStringNotEqual, "helper.s_ne");
    registry->registerBuilder(builders::opBuilderHelperStringStarts, "helper.s_starts");
    // Filter helpers: Event Field functions
    registry->registerBuilder(builders::opBuilderHelperExists, "helper.ef_exists");
    registry->registerBuilder(builders::opBuilderHelperNotExists, "helper.ef_not_exists");

    // Map Helpers
    registry->registerBuilder(builders::opBuilderHelperIntCalc, "helper.i_calc");
    registry->registerBuilder(builders::opBuilderHelperRegexExtract, "helper.r_ext");
    // Map helpers: Event Field functions
    registry->registerBuilder(builders::opBuilderHelperDeleteField, "helper.ef_delete");
    registry->registerBuilder(builders::opBuilderHelperMerge, "helper.ef_merge");
    registry->registerBuilder(builders::opBuilderHelperRenameField, "helper.ef_rename");
    // Map helpers: Hash functions
    registry->registerBuilder(builders::opBuilderHelperHashSHA1, "helper.h_sha1");
    // Map helpers: String functions
    registry->registerBuilder(builders::opBuilderHelperAppendSplitString,
                              "helper.s_to_array");
    registry->registerBuilder(builders::opBuilderHelperAppend, "helper.a_append");
    registry->registerBuilder(builders::opBuilderHelperHexToNumber,
                              "helper.s_hex_to_num");
    registry->registerBuilder(builders::opBuilderHelperIPVersionFromIPStr,
                              "helper.s_ip_version");
    registry->registerBuilder(builders::opBuilderHelperStringConcat, "helper.s_concat");
    registry->registerBuilder(builders::opBuilderHelperStringFromArray,
                              "helper.s_from_array");
    registry->registerBuilder(builders::opBuilderHelperStringFromHexa,
                              "helper.s_from_hexa");
    registry->registerBuilder(builders::opBuilderHelperStringLO, "helper.s_lo");
    registry->registerBuilder(builders::opBuilderHelperStringReplace, "helper.s_replace");
    registry->registerBuilder(builders::opBuilderHelperStringTrim, "helper.s_trim");
    registry->registerBuilder(builders::opBuilderHelperStringUP, "helper.s_up");
    // Map helpers: Time functions
    registry->registerBuilder(builders::opBuilderHelperEpochTimeFromSystem,
                              "helper.sys_epoch");

    // Special helpers

    // Active Response
    registry->registerBuilder(builders::opBuilderHelperCreateAR, "helper.ar_create");
    registry->registerBuilder(builders::opBuilderHelperSendAR, "helper.ar_send");

    // DB sync
    registry->registerBuilder(builders::opBuilderWdbQuery, "helper.wdb_query");
    registry->registerBuilder(builders::opBuilderWdbUpdate, "helper.wdb_update");

    // KVDB
    registry->registerBuilder(builders::getOpBuilderKVDBExtract(dependencies.kvdbManager),
                              "helper.kvdb_get");
    registry->registerBuilder(
        builders::getOpBuilderKVDBExtractMerge(dependencies.kvdbManager),
        "helper.kvdb_get_merge");
    registry->registerBuilder(builders::getOpBuilderKVDBMatch(dependencies.kvdbManager),
                              "helper.kvdb_match");
    registry->registerBuilder(
        builders::getOpBuilderKVDBNotMatch(dependencies.kvdbManager),
        "helper.kvdb_not_match");

    // SCA decoder
    registry->registerBuilder(builders::opBuilderSCAdecoder, "helper.sca_decoder");

    // SysCollector - netInfo
    registry->registerBuilder(builders::opBuilderHelperSaveNetInfoIPv4,
                              "helper.sysc_ni_save_ipv4");
    registry->registerBuilder(builders::opBuilderHelperSaveNetInfoIPv6,
                              "helper.sysc_ni_save_ipv6");

    // High level parsers
    registry->registerBuilder(builders::opBuilderSpecificHLPBoolParse,
                              "helper.parse_bool");
    registry->registerBuilder(builders::opBuilderSpecificHLPByteParse,
                              "helper.parse_byte");
    registry->registerBuilder(builders::opBuilderSpecificHLPLongParse,
                              "helper.parse_long");
    registry->registerBuilder(builders::opBuilderSpecificHLPFloatParse,
                              "helper.parse_float");
    registry->registerBuilder(builders::opBuilderSpecificHLPDoubleParse,
                              "helper.parse_double");
    registry->registerBuilder(builders::opBuilderSpecificHLPBinaryParse,
                              "helper.parse_binary");
    registry->registerBuilder(builders::opBuilderSpecificHLPDateParse,
                              "helper.parse_date");
    registry->registerBuilder(builders::opBuilderSpecificHLPIPParse, "helper.parse_ip");
    registry->registerBuilder(builders::opBuilderSpecificHLPURIParse, "helper.parse_uri");
    registry->registerBuilder(builders::opBuilderSpecificHLPUserAgentParse,
                              "helper.parse_useragent");
    registry->registerBuilder(builders::opBuilderSpecificHLPFQDNParse,
                              "helper.parse_fqdn");
    registry->registerBuilder(builders::opBuilderSpecificHLPFilePathParse,
                              "helper.parse_file");
    registry->registerBuilder(builders::opBuilderSpecificHLPJSONParse,
                              "helper.parse_json");
    registry->registerBuilder(builders::opBuilderSpecificHLPXMLParse, "helper.parse_xml");
    registry->registerBuilder(builders::opBuilderSpecificHLPCSVParse, "helper.parse_csv");
    registry->registerBuilder(builders::opBuilderSpecificHLPDSVParse, "helper.parse_dsv");
    registry->registerBuilder(builders::opBuilderSpecificHLPKeyValueParse,
                              "helper.parse_kv");
    registry->registerBuilder(builders::opBuilderSpecificHLPQuotedParse,
                              "helper.parse_quoted");
    registry->registerBuilder(builders::opBuilderSpecificHLPBetweenParse,
                              "helper.parse_between");
}
} // namespace builder::internals

#endif // _REGISTER_H

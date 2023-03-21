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
    size_t logparDebugLvl;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;
};

static void registerBuilders(std::shared_ptr<Registry> registry, const dependencies& dependencies = {})
{
    // Basic operations
    registry->registerBuilder(builders::getOperationMapBuilder(registry), "operation.map");
    registry->registerBuilder(builders::getOperationConditionBuilder(registry), "operation.condition");

    // Stages
    registry->registerBuilder(builders::getStageBuilderCheck(registry), "stage.check", "stage.allow");
    registry->registerBuilder(builders::getStageMapBuilder(registry), "stage.map");
    registry->registerBuilder(builders::getStageNormalizeBuilder(registry), "stage.normalize");

    // Parsers
    registry->registerBuilder(builders::getStageBuilderParse(registry), "stage.parse");
    registry->registerBuilder(builders::getOpBuilderLogParser(dependencies.logpar, dependencies.logparDebugLvl),
                              "parser.logpar");

    // Outputs
    registry->registerBuilder(builders::getStageBuilderOutputs(registry), "stage.outputs");
    registry->registerBuilder(builders::opBuilderFileOutput, "output.file");

    // Filter Helpers
    registry->registerBuilder(builders::opBuilderHelperContainsString, "helper.array_contains");
    registry->registerBuilder(builders::opBuilderHelperIntEqual, "helper.int_equal");
    registry->registerBuilder(builders::opBuilderHelperIntGreaterThan, "helper.int_greater");
    registry->registerBuilder(builders::opBuilderHelperIntGreaterThanEqual, "helper.int_greater_or_equal");
    registry->registerBuilder(builders::opBuilderHelperIntLessThan, "helper.int_less");
    registry->registerBuilder(builders::opBuilderHelperIntLessThanEqual, "helper.int_less_or_equal");
    registry->registerBuilder(builders::opBuilderHelperIntNotEqual, "helper.int_not_equal");
    registry->registerBuilder(builders::opBuilderHelperIPCIDR, "helper.ip_cidr_match");
    registry->registerBuilder(builders::opBuilderHelperIsArray, "helper.is_array");
    registry->registerBuilder(builders::opBuilderHelperIsBool, "helper.is_boolean");
    registry->registerBuilder(builders::opBuilderHelperIsFalse, "helper.is_false");
    registry->registerBuilder(builders::opBuilderHelperIsNotArray, "helper.is_not_array");
    registry->registerBuilder(builders::opBuilderHelperIsNotBool, "helper.is_not_boolean");
    registry->registerBuilder(builders::opBuilderHelperIsNotNull, "helper.is_not_null");
    registry->registerBuilder(builders::opBuilderHelperIsNotNumber, "helper.is_not_number");
    registry->registerBuilder(builders::opBuilderHelperIsNotObject, "helper.is_not_object");
    registry->registerBuilder(builders::opBuilderHelperIsNotString, "helper.is_not_string");
    registry->registerBuilder(builders::opBuilderHelperIsNull, "helper.is_null");
    registry->registerBuilder(builders::opBuilderHelperIsNumber, "helper.is_number");
    registry->registerBuilder(builders::opBuilderHelperIsObject, "helper.is_object");
    registry->registerBuilder(builders::opBuilderHelperIsString, "helper.is_string");
    registry->registerBuilder(builders::opBuilderHelperIsTrue, "helper.is_true");
    registry->registerBuilder(builders::opBuilderHelperRegexMatch, "helper.regex_match");
    registry->registerBuilder(builders::opBuilderHelperRegexNotMatch, "helper.regex_not_match");
    registry->registerBuilder(builders::opBuilderHelperStringEqual, "helper.string_equal");
    registry->registerBuilder(builders::opBuilderHelperStringGreaterThan, "helper.string_greater");
    registry->registerBuilder(builders::opBuilderHelperStringGreaterThanEqual, "helper.string_greater_or_equal");
    registry->registerBuilder(builders::opBuilderHelperStringLessThan, "helper.string_less");
    registry->registerBuilder(builders::opBuilderHelperStringLessThanEqual, "helper.string_less_or_equal");
    registry->registerBuilder(builders::opBuilderHelperStringNotEqual, "helper.string_not_equal");
    registry->registerBuilder(builders::opBuilderHelperStringStarts, "helper.starts_with");
    // Filter helpers: Event Field functions
    registry->registerBuilder(builders::opBuilderHelperExists, "helper.exists");
    registry->registerBuilder(builders::opBuilderHelperNotExists, "helper.not_exists");

    // Map Helpers
    registry->registerBuilder(builders::opBuilderHelperIntCalc, "helper.int_calculate");
    registry->registerBuilder(builders::opBuilderHelperRegexExtract, "helper.regex_extract");
    // Map helpers: Event Field functions
    registry->registerBuilder(builders::opBuilderHelperDeleteField, "helper.delete");
    registry->registerBuilder(builders::opBuilderHelperMerge, "helper.merge");
    registry->registerBuilder(builders::opBuilderHelperMergeRecursively, "helper.merge_recursive");
    registry->registerBuilder(builders::opBuilderHelperRenameField, "helper.rename");
    // Map helpers: Hash functions
    registry->registerBuilder(builders::opBuilderHelperHashSHA1, "helper.sha1");
    // Map helpers: String functions
    registry->registerBuilder(builders::opBuilderHelperAppendSplitString, "helper.split");
    registry->registerBuilder(builders::opBuilderHelperAppend, "helper.array_append");
    registry->registerBuilder(builders::opBuilderHelperHexToNumber, "helper.hex_to_number");
    registry->registerBuilder(builders::opBuilderHelperIPVersionFromIPStr, "helper.ip_version");
    registry->registerBuilder(builders::opBuilderHelperStringConcat, "helper.concat");
    registry->registerBuilder(builders::opBuilderHelperStringFromArray, "helper.join");
    registry->registerBuilder(builders::opBuilderHelperStringFromHexa, "helper.decode_base16");
    registry->registerBuilder(builders::opBuilderHelperStringLO, "helper.downcase");
    registry->registerBuilder(builders::opBuilderHelperStringReplace, "helper.replace");
    registry->registerBuilder(builders::opBuilderHelperStringTrim, "helper.trim");
    registry->registerBuilder(builders::opBuilderHelperStringUP, "helper.upcase");
    registry->registerBuilder(builders::opBuilderHelperStringContains, "helper.contains");
    // Map helpers: Time functions
    registry->registerBuilder(builders::opBuilderHelperEpochTimeFromSystem, "helper.system_epoch");

    // Special helpers

    // Active Response
    registry->registerBuilder(builders::opBuilderHelperCreateAR, "helper.active_response_create");
    registry->registerBuilder(builders::opBuilderHelperSendAR, "helper.active_response_send");

    // DB sync
    registry->registerBuilder(builders::opBuilderWdbQuery, "helper.wdb_query");
    registry->registerBuilder(builders::opBuilderWdbUpdate, "helper.wdb_update");

    // KVDB
    registry->registerBuilder(builders::getOpBuilderKVDBDelete(dependencies.kvdbManager), "helper.kvdb_delete");
    registry->registerBuilder(builders::getOpBuilderKVDBGet(dependencies.kvdbManager), "helper.kvdb_get");
    registry->registerBuilder(builders::getOpBuilderKVDBGetMerge(dependencies.kvdbManager), "helper.kvdb_get_merge");
    registry->registerBuilder(builders::getOpBuilderKVDBMatch(dependencies.kvdbManager), "helper.kvdb_match");
    registry->registerBuilder(builders::getOpBuilderKVDBNotMatch(dependencies.kvdbManager), "helper.kvdb_not_match");
    registry->registerBuilder(builders::getOpBuilderKVDBSet(dependencies.kvdbManager), "helper.kvdb_set");

    // SCA decoder
    registry->registerBuilder(builders::opBuilderSCAdecoder, "helper.sca_decoder");

    // SysCollector - netInfo
    registry->registerBuilder(builders::opBuilderHelperSaveNetInfoIPv4, "helper.sysc_ni_save_ipv4");
    registry->registerBuilder(builders::opBuilderHelperSaveNetInfoIPv6, "helper.sysc_ni_save_ipv6");

    // High level parsers
    registry->registerBuilder(builders::opBuilderSpecificHLPBoolParse, "helper.parse_bool");
    registry->registerBuilder(builders::opBuilderSpecificHLPByteParse, "helper.parse_byte");
    registry->registerBuilder(builders::opBuilderSpecificHLPLongParse, "helper.parse_long");
    registry->registerBuilder(builders::opBuilderSpecificHLPFloatParse, "helper.parse_float");
    registry->registerBuilder(builders::opBuilderSpecificHLPDoubleParse, "helper.parse_double");
    registry->registerBuilder(builders::opBuilderSpecificHLPBinaryParse, "helper.parse_binary");
    registry->registerBuilder(builders::opBuilderSpecificHLPDateParse, "helper.parse_date");
    registry->registerBuilder(builders::opBuilderSpecificHLPIPParse, "helper.parse_ip");
    registry->registerBuilder(builders::opBuilderSpecificHLPURIParse, "helper.parse_uri");
    registry->registerBuilder(builders::opBuilderSpecificHLPUserAgentParse, "helper.parse_useragent");
    registry->registerBuilder(builders::opBuilderSpecificHLPFQDNParse, "helper.parse_fqdn");
    registry->registerBuilder(builders::opBuilderSpecificHLPFilePathParse, "helper.parse_file");
    registry->registerBuilder(builders::opBuilderSpecificHLPJSONParse, "helper.parse_json");
    registry->registerBuilder(builders::opBuilderSpecificHLPXMLParse, "helper.parse_xml");
    registry->registerBuilder(builders::opBuilderSpecificHLPCSVParse, "helper.parse_csv");
    registry->registerBuilder(builders::opBuilderSpecificHLPDSVParse, "helper.parse_dsv");
    registry->registerBuilder(builders::opBuilderSpecificHLPKeyValueParse, "helper.parse_key_value");
    registry->registerBuilder(builders::opBuilderSpecificHLPQuotedParse, "helper.parse_quoted");
    registry->registerBuilder(builders::opBuilderSpecificHLPBetweenParse, "helper.parse_between");
    registry->registerBuilder(builders::opBuilderSpecificHLPAlphanumericParse, "helper.parse_alphanumeric");
}
} // namespace builder::internals

#endif // _REGISTER_H

#ifndef _REGISTER_H
#define _REGISTER_H

#include <logpar/logpar.hpp>
#include <kvdb/kvdbManager.hpp>
#include <kvdb2/kvdbManager.hpp>
#include <schemf/ischema.hpp>

#include "builders/opBuilderFileOutput.hpp"
#include "builders/opBuilderHelperActiveResponse.hpp"
#include "builders/opBuilderHelperFilter.hpp"
#include "builders/opBuilderHelperMap.hpp"
#include "builders/opBuilderHelperNetInfoAddress.hpp"
#include "builders/opBuilderHelperUpgradeConfirmation.hpp"
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
    std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope;
    std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager2;
    std::shared_ptr<Registry<HelperBuilder>> helperRegistry;
    std::shared_ptr<schemf::ISchema> schema;
    bool forceFieldNaming = false; // TODO remove once test use proper naming for fields
};

static void registerHelperBuilders(std::shared_ptr<Registry<HelperBuilder>> helperRegistry,
                                   const dependencies& dependencies = {})
{
    // Filter Helpers
    helperRegistry->registerBuilder(builders::opBuilderHelperContainsString, "array_contains");
    helperRegistry->registerBuilder(builders::opBuilderHelperNotContainsString, "array_not_contains");
    helperRegistry->registerBuilder(builders::opBuilderHelperIntEqual, "int_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperIntGreaterThan, "int_greater");
    helperRegistry->registerBuilder(builders::opBuilderHelperIntGreaterThanEqual, "int_greater_or_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperIntLessThan, "int_less");
    helperRegistry->registerBuilder(builders::opBuilderHelperIntLessThanEqual, "int_less_or_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperIntNotEqual, "int_not_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperIPCIDR, "ip_cidr_match");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsArray, "is_array");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsBool, "is_boolean");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsFalse, "is_false");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNotArray, "is_not_array");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNotBool, "is_not_boolean");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNotNull, "is_not_null");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNotNumber, "is_not_number");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNotObject, "is_not_object");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNotString, "is_not_string");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNull, "is_null");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsNumber, "is_number");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsObject, "is_object");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsString, "is_string");
    helperRegistry->registerBuilder(builders::opBuilderHelperIsTrue, "is_true");
    helperRegistry->registerBuilder(builders::opBuilderHelperRegexMatch, "regex_match");
    helperRegistry->registerBuilder(builders::opBuilderHelperRegexNotMatch, "regex_not_match");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringEqual, "string_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringGreaterThan, "string_greater");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringGreaterThanEqual, "string_greater_or_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringLessThan, "string_less");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringLessThanEqual, "string_less_or_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringNotEqual, "string_not_equal");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringStarts, "starts_with");
    helperRegistry->registerBuilder(builders::opBuilderHelperExists, "exists");
    helperRegistry->registerBuilder(builders::opBuilderHelperNotExists, "not_exists");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringContains, "contains");
    helperRegistry->registerBuilder(builders::opBuilderHelperMatchValue, "match_value");
    helperRegistry->registerBuilder(builders::getOpBuilderHelperMatchKey(dependencies.schema), "match_key");

    // Map Helpers
    helperRegistry->registerBuilder(builders::opBuilderHelperIntCalc, "int_calculate");
    helperRegistry->registerBuilder(builders::opBuilderHelperRegexExtract, "regex_extract");
    // Map helpers: Event Field functions
    helperRegistry->registerBuilder(builders::opBuilderHelperDeleteField, "delete");
    helperRegistry->registerBuilder(builders::opBuilderHelperMerge, "merge");
    helperRegistry->registerBuilder(builders::opBuilderHelperMergeRecursively, "merge_recursive");
    helperRegistry->registerBuilder(builders::opBuilderHelperRenameField, "rename");
    // Map helpers: Hash functions
    helperRegistry->registerBuilder(builders::opBuilderHelperHashSHA1, "sha1");
    // Map helpers: String functions
    helperRegistry->registerBuilder(builders::opBuilderHelperAppendSplitString, "split");
    helperRegistry->registerBuilder(builders::opBuilderHelperAppend, "array_append");
    helperRegistry->registerBuilder(builders::opBuilderHelperHexToNumber, "hex_to_number");
    helperRegistry->registerBuilder(builders::opBuilderHelperIPVersionFromIPStr, "ip_version");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringConcat, "concat");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringFromArray, "join");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringFromHexa, "decode_base16");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringLO, "downcase");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringReplace, "replace");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringTrim, "trim");
    helperRegistry->registerBuilder(builders::opBuilderHelperStringUP, "upcase");
    // Map helpers: Time functions
    helperRegistry->registerBuilder(builders::opBuilderHelperEpochTimeFromSystem, "system_epoch");
    helperRegistry->registerBuilder(builders::getOpBuilderHelperDateFromEpochTime(dependencies.schema), "date_from_epoch");
    // Map helpers: Definition functions
    helperRegistry->registerBuilder(builders::getOpBuilderHelperGetValue(dependencies.schema), "get_value");
    helperRegistry->registerBuilder(builders::getOpBuilderHelperMergeValue(dependencies.schema), "merge_value");

    // Special helpers

    // Active Response
    helperRegistry->registerBuilder(builders::opBuilderHelperCreateAR, "active_response_create");
    helperRegistry->registerBuilder(builders::opBuilderHelperSendAR, "active_response_send");

    // DB sync
    helperRegistry->registerBuilder(builders::opBuilderWdbQuery, "wdb_query");
    helperRegistry->registerBuilder(builders::opBuilderWdbUpdate, "wdb_update");

    // KVDB
    helperRegistry->registerBuilder(builders::getOpBuilderKVDBDelete(dependencies.kvdbManager2), "kvdb_delete");
    helperRegistry->registerBuilder(builders::getOpBuilderKVDBGet(dependencies.kvdbScope), "kvdb_get");
    helperRegistry->registerBuilder(builders::getOpBuilderKVDBGetMerge(dependencies.kvdbScope), "kvdb_get_merge");
    helperRegistry->registerBuilder(builders::getOpBuilderKVDBMatch(dependencies.kvdbScope), "kvdb_match");
    helperRegistry->registerBuilder(builders::getOpBuilderKVDBNotMatch(dependencies.kvdbScope), "kvdb_not_match");
    helperRegistry->registerBuilder(builders::getOpBuilderKVDBSet(dependencies.kvdbScope), "kvdb_set");

    // SCA decoder
    helperRegistry->registerBuilder(builders::opBuilderSCAdecoder, "sca_decoder");

    // SysCollector - netInfo
    helperRegistry->registerBuilder(builders::opBuilderHelperSaveNetInfoIPv4, "sysc_ni_save_ipv4");
    helperRegistry->registerBuilder(builders::opBuilderHelperSaveNetInfoIPv6, "sysc_ni_save_ipv6");

    // High level parsers
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPBoolParse, "parse_bool");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPByteParse, "parse_byte");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPLongParse, "parse_long");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPFloatParse, "parse_float");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPDoubleParse, "parse_double");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPBinaryParse, "parse_binary");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPDateParse, "parse_date");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPIPParse, "parse_ip");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPURIParse, "parse_uri");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPUserAgentParse, "parse_useragent");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPFQDNParse, "parse_fqdn");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPFilePathParse, "parse_file");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPJSONParse, "parse_json");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPXMLParse, "parse_xml");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPCSVParse, "parse_csv");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPDSVParse, "parse_dsv");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPKeyValueParse, "parse_key_value");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPQuotedParse, "parse_quoted");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPBetweenParse, "parse_between");
    helperRegistry->registerBuilder(builders::opBuilderSpecificHLPAlphanumericParse, "parse_alphanumeric");

    // Upgrade Confirmation
    helperRegistry->registerBuilder(builders::opBuilderHelperSendUpgradeConfirmation, "send_upgrade_confirmation");
}

static void registerBuilders(std::shared_ptr<Registry<Builder>> registry, const dependencies& dependencies = {})
{
    // Basic operations
    registry->registerBuilder(builders::getOperationMapBuilder(
                                  dependencies.helperRegistry, dependencies.schema, dependencies.forceFieldNaming),
                              "operation.map");
    registry->registerBuilder(builders::getOperationConditionBuilder(
                                  dependencies.helperRegistry, dependencies.schema, dependencies.forceFieldNaming),
                              "operation.condition");

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
}
} // namespace builder::internals

#endif // _REGISTER_H

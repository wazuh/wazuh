// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef BUILDER2_REGISTER_HPP
#define BUILDER2_REGISTER_HPP

#include <memory>

#include "builder/builder.hpp"
#include "iregistry.hpp"
#include "schemf/ivalidator.hpp"
#include "syntax.hpp"

// Filter builders
#include "builders/opfilter/exists.hpp"
#include "builders/opfilter/filter.hpp"
#include "builders/opfilter/opBuilderHelperFilter.hpp"

// Map builders
#include "builders/opmap/map.hpp"
#include "builders/opmap/mmdb.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

// Transform builders
#include "builders/opmap/kvdb.hpp"
#include "builders/optransform/array.hpp"
#include "builders/optransform/hlp.hpp"
#include "builders/optransform/windows.hpp"

// Stage builders
#include "builders/stage/check.hpp"
#include "builders/stage/fileOutput.hpp"
#include "builders/stage/first_of.hpp"
#include "builders/stage/indexerOutput.hpp"
#include "builders/stage/map.hpp"
#include "builders/stage/normalize.hpp"
#include "builders/stage/outputs.hpp"
#include "builders/stage/parse.hpp"

// Enrichment builders
#include "builders/enrichment/enrichment.hpp"
#include "iockvdb/helpers.hpp"

namespace builder::detail
{

const base::Name STORE_GEO_CONFIG_DOC_NAME {"enrichment/geo/0"};
const base::Name STORE_IOC_CONFIG_DOC_NAME {"enrichment/ioc/0"};

/*
 * Helper names follow the naming convention in src/engine/source/builder/src/builders/README.md ("Naming
 * Convention"); docs/ref/modules/engine/README.md ("Helper functions") carries the copy for content authors. Read it
 * before adding a helper, then:
 *  - register the helper below under its kind (check, map, transform) with the validation token it needs;
 *  - add src/engine/test/helper_tests/helpers_description/<check|map|transform>/<name>.yml with the same name (the
 *    engine-helper-test tool validates it and generates its tests; the registry and the YAML set must stay equal);
 *  - regenerate docs/ref/modules/engine/ref-helper-functions.md with `engine-helper-test generate-doc` (CI diffs
 *    the committed copy).
 * Renaming a helper is a hard break: there are no aliases and no rename hints, so the content that uses it moves in
 * the same release.
 */

/**
 * @brief Register all operation (helper) builders in the registry.
 *
 * @tparam Registry Registry type
 * @param registry Registry instance
 * @param deps Builders dependencies
 */
template<typename Registry>
void registerOpBuilders(const std::shared_ptr<Registry>& registry, const builder::BuilderDeps& deps)
{
    // Check helpers (the "filter" entry is the implicit equality check used by `field: value` and `==`)
    registry->template add<builders::OpBuilderEntry>(
        "filter", {builders::opfilter::filterValidator(), builders::opfilter::filterBuilder});
    registry->template add<builders::OpBuilderEntry>("exists",
                                                     {schemf::runtimeValidation(), builders::opfilter::existsBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "not_exists", {schemf::runtimeValidation(), builders::opfilter::notExistsBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "array_contains_all", {schemf::elementValidationToken(), builders::opfilter::opBuilderHelperContains});
    registry->template add<builders::OpBuilderEntry>(
        "array_contains_any", {schemf::elementValidationToken(), builders::opfilter::opBuilderHelperContainsAny});
    registry->template add<builders::OpBuilderEntry>(
        "array_contains_none", {schemf::elementValidationToken(), builders::opfilter::opBuilderHelperNotContainsAny});
    registry->template add<builders::OpBuilderEntry>(
        "number_eq",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperNumberEqual});
    registry->template add<builders::OpBuilderEntry>(
        "number_gt",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperNumberGreaterThan});
    registry->template add<builders::OpBuilderEntry>("number_gte",
                                                     {schemf::JTypeToken::create(json::Json::Type::Number),
                                                      builders::opfilter::opBuilderHelperNumberGreaterThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "number_lt",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperNumberLessThan});
    registry->template add<builders::OpBuilderEntry>(
        "number_lte",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperNumberLessThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "number_ne",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperNumberNotEqual});
    registry->template add<builders::OpBuilderEntry>(
        "in_cidr", {schemf::STypeToken::create(schemf::Type::IP), builders::opfilter::opBuilderHelperIPCIDR});
    registry->template add<builders::OpBuilderEntry>(
        "is_public_ip", {schemf::STypeToken::create(schemf::Type::IP), builders::opfilter::opBuilderHelperPublicIP});
    registry->template add<builders::OpBuilderEntry>(
        "is_ipv4", {schemf::STypeToken::create(schemf::Type::IP), builders::opfilter::opBuilderHelperIsIpv4});
    registry->template add<builders::OpBuilderEntry>(
        "is_ipv6", {schemf::STypeToken::create(schemf::Type::IP), builders::opfilter::opBuilderHelperIsIpv6});
    registry->template add<builders::OpBuilderEntry>(
        "is_array", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsArray});
    registry->template add<builders::OpBuilderEntry>(
        "is_boolean", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsBool});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_array", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNotArray});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_boolean", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNotBool});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_null", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNotNull});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_number", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNotNumber});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_object", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNotObject});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_string", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNotString});
    registry->template add<builders::OpBuilderEntry>(
        "is_null", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNull});
    registry->template add<builders::OpBuilderEntry>(
        "is_number", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsNumber});
    registry->template add<builders::OpBuilderEntry>(
        "is_object", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsObject});
    registry->template add<builders::OpBuilderEntry>(
        "is_string", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperIsString});
    registry->template add<builders::OpBuilderEntry>(
        "has_only_keys",
        {schemf::JTypeToken::create(json::Json::Type::Object), builders::opfilter::opBuilderHelperKeysExistInList});
    registry->template add<builders::OpBuilderEntry>(
        "has_any_bit", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperBinaryAnd});
    registry->template add<builders::OpBuilderEntry>(
        "regex_match",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperRegexMatch});
    registry->template add<builders::OpBuilderEntry>(
        "regex_not_match",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperRegexNotMatch});
    registry->template add<builders::OpBuilderEntry>(
        "string_eq",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_gt",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringGreaterThan});
    registry->template add<builders::OpBuilderEntry>("string_gte",
                                                     {schemf::JTypeToken::create(json::Json::Type::String),
                                                      builders::opfilter::opBuilderHelperStringGreaterThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_lt",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringLessThan});
    registry->template add<builders::OpBuilderEntry>(
        "string_lte",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringLessThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_ne",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringNotEqual});
    registry->template add<builders::OpBuilderEntry>(
        "starts_with",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringStarts});
    registry->template add<builders::OpBuilderEntry>(
        "ends_with",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperEndsWith});
    registry->template add<builders::OpBuilderEntry>(
        "contains",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringContains});
    registry->template add<builders::OpBuilderEntry>(
        "one_of", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperMatchValue});
    registry->template add<builders::OpBuilderEntry>(
        "is_key_of",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperMatchKey});
    registry->template add<builders::OpBuilderEntry>(
        "array_length_eq", {schemf::elementValidationToken(), builders::opfilter::opBuilderHelperArrayLength});
    registry->template add<builders::OpBuilderEntry>(
        "index_unclassified_events",
        {schemf::elementValidationToken(), builders::opfilter::opBuilderHelperIndexUnclassifiedEvents});

    // Map helpers (the "map" entry is the implicit assignment used by `field: value`)
    registry->template add<builders::OpBuilderEntry>("map",
                                                     {builders::opmap::mapValidator(), builders::opmap::mapBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "to_string", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperNumberToString});
    registry->template add<builders::OpBuilderEntry>(
        "int_calculate",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::getOpBuilderHelperCalc(true)});
    registry->template add<builders::OpBuilderEntry>(
        "float_calculate",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::getOpBuilderHelperCalc(false)});
    registry->template add<builders::OpBuilderEntry>(
        "regex_extract", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperRegexExtract});
    registry->template add<builders::OpBuilderEntry>(
        "regex_extract_all",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperRegexExtractAll});
    // Map helpers: Hash functions
    registry->template add<builders::OpBuilderEntry>(
        "sha1", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperHashSHA1});
    registry->template add<builders::OpBuilderEntry>(
        "hex_to_int", {schemf::JTypeToken::create(json::Json::Type::Number), builders::opBuilderHelperHexToNumber});
    registry->template add<builders::OpBuilderEntry>(
        "iana_protocol_number",
        {schemf::STypeToken::create(schemf::Type::KEYWORD), builders::opBuilderHelperIanaProtocolNameToNumber});
    registry->template add<builders::OpBuilderEntry>(
        "iana_protocol_name",
        {schemf::STypeToken::create(schemf::Type::KEYWORD), builders::opBuilderHelperIanaProtocolNumberToName});
    registry->template add<builders::OpBuilderEntry>(
        "ip_version",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperIPVersionFromIPStr});
    registry->template add<builders::OpBuilderEntry>(
        "community_id",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperNetworkCommunityId});
    registry->template add<builders::OpBuilderEntry>(
        "syslog_facility",
        {schemf::JTypeToken::create(json::Json::Type::Object), builders::opBuilderHelperSyslogExtractFacility});
    registry->template add<builders::OpBuilderEntry>(
        "syslog_severity",
        {schemf::JTypeToken::create(json::Json::Type::Object), builders::opBuilderHelperSyslogExtractSeverity});
    registry->template add<builders::OpBuilderEntry>(
        "join", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringFromArray});
    registry->template add<builders::OpBuilderEntry>(
        "decode_hex", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringFromHexa});
    registry->template add<builders::OpBuilderEntry>(
        "lowercase", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringLO});
    registry->template add<builders::OpBuilderEntry>(
        "uppercase", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringUP});
    // Map helpers: Time functions
    registry->template add<builders::OpBuilderEntry>(
        "now_epoch", {schemf::STypeToken::create(schemf::Type::LONG), builders::opBuilderHelperEpochTimeFromSystem});
    registry->template add<builders::OpBuilderEntry>(
        "epoch_to_date", {schemf::STypeToken::create(schemf::Type::DATE), builders::opBuilderHelperDateFromEpochTime});
    registry->template add<builders::OpBuilderEntry>(
        "date_to_epoch", {schemf::STypeToken::create(schemf::Type::DOUBLE), builders::opBuilderHelperDateToEpochTime});
    registry->template add<builders::OpBuilderEntry>(
        "now", {schemf::STypeToken::create(schemf::Type::DATE), builders::opBuilderHelperGetDate});

    // Transform helpers: array functions
    registry->template add<builders::OpBuilderEntry>(
        "array_append_unique",
        {schemf::elementValidationToken(), builders::optransform::getArrayAppendBuilder(true, false)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append", {schemf::elementValidationToken(), builders::optransform::getArrayAppendBuilder(false, false)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append_unique_any",
        {schemf::elementValidationToken(), builders::optransform::getArrayAppendBuilder(true, true)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append_any",
        {schemf::elementValidationToken(), builders::optransform::getArrayAppendBuilder(false, true)});
    // Transform helpers: Event Field functions
    registry->template add<builders::OpBuilderEntry>(
        "delete", {schemf::runtimeValidation(), builders::opBuilderHelperDeleteField});
    registry->template add<builders::OpBuilderEntry>(
        "delete_fields_with_value", {schemf::runtimeValidation(), builders::opBuilderHelperDeleteFieldsWithValue});
    // TODO: this builders should check that the field is an array or an object
    registry->template add<builders::OpBuilderEntry>("merge",
                                                     {schemf::runtimeValidation(), builders::opBuilderHelperMerge});
    registry->template add<builders::OpBuilderEntry>(
        "rename", {schemf::runtimeValidation(), builders::opBuilderHelperRenameField});
    // Transform helpers: String functions
    registry->template add<builders::OpBuilderEntry>(
        "split", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperAppendSplitString});
    registry->template add<builders::OpBuilderEntry>(
        "array_to_object",
        {schemf::JTypeToken::create(json::Json::Type::Object), builders::opBuilderHelperArrayObjToMapkv});
    registry->template add<builders::OpBuilderEntry>(
        "array_to_object_changes",
        {schemf::JTypeToken::create(json::Json::Type::Object), builders::opBuilderHelperArrayExtractKeyObj});
    registry->template add<builders::OpBuilderEntry>(
        "concat", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringConcat()});
    registry->template add<builders::OpBuilderEntry>(
        "concat_any",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringConcat(true)});
    registry->template add<builders::OpBuilderEntry>(
        "replace", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringReplace});
    registry->template add<builders::OpBuilderEntry>(
        "trim", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringTrim});
    registry->template add<builders::OpBuilderEntry>(
        "trim_start", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringTrimStart});
    registry->template add<builders::OpBuilderEntry>(
        "trim_end", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringTrimEnd});
    registry->template add<builders::OpBuilderEntry>(
        "to_int", {schemf::JTypeToken::create(json::Json::Type::Number), builders::opBuilderHelperToInt});
    // Register the to_bool helper (boolean result)
    registry->template add<builders::OpBuilderEntry>(
        "to_bool", {schemf::STypeToken::create(schemf::Type::BOOLEAN), builders::opBuilderHelperToBool});
    // Transform helpers: inline object (table) functions
    registry->template add<builders::OpBuilderEntry>(
        "lookup", {schemf::runtimeValidation(), builders::opBuilderHelperGetValue}); // TODO: add validation
    registry->template add<builders::OpBuilderEntry>(
        "lookup_merge", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::opBuilderHelperMergeValue});
    // Map helpers: MMDB functions
    registry->template add<builders::OpBuilderEntry>(
        "geoip",
        {schemf::STypeToken::create(schemf::Type::OBJECT), builders::mmdb::getMMDBGeoBuilder(deps.geoManager)});
    registry->template add<builders::OpBuilderEntry>(
        "asn", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::mmdb::getMMDBASNBuilder(deps.geoManager)});
    // Global event helpers
    registry->template add<builders::OpBuilderEntry>(
        "delete_custom_fields", {schemf::runtimeValidation(), builders::opBuilderHelperEraseCustomFields});
    registry->template add<builders::OpBuilderEntry>(
        "snake_case_keys", {schemf::runtimeValidation(), builders::opBuilderHelperSanitizeFields});
    registry->template add<builders::OpBuilderEntry>(
        "discard_event", {schemf::runtimeValidation(), builders::opBuilderHelperDiscardEvents});
    // HLP Parser helpers
    registry->template add<builders::OpBuilderEntry>(
        "parse_bool", {schemf::STypeToken::create(schemf::Type::BOOLEAN), builders::optransform::boolParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_byte", {schemf::STypeToken::create(schemf::Type::BYTE), builders::optransform::byteParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_long", {schemf::STypeToken::create(schemf::Type::LONG), builders::optransform::longParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_float", {schemf::STypeToken::create(schemf::Type::FLOAT), builders::optransform::floatParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_half_float",
        {schemf::STypeToken::create(schemf::Type::HALF_FLOAT), builders::optransform::halfFloatParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_double", {schemf::STypeToken::create(schemf::Type::DOUBLE), builders::optransform::doubleParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_unsigned_long",
        {schemf::STypeToken::create(schemf::Type::UNSIGNED_LONG), builders::optransform::unsignedLongParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_integer",
        {schemf::STypeToken::create(schemf::Type::INTEGER), builders::optransform::integerParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_short", {schemf::STypeToken::create(schemf::Type::SHORT), builders::optransform::shortParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_binary", {schemf::STypeToken::create(schemf::Type::BINARY), builders::optransform::binaryParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_date", {schemf::STypeToken::create(schemf::Type::DATE), builders::optransform::dateParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_ip", {schemf::STypeToken::create(schemf::Type::IP), builders::optransform::ipParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_uri", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::uriParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_fqdn", {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::fqdnParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_file", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::filePathParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_json", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::jsonParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_xml", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::xmlParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_csv", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::csvParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_dsv", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::dsvParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_kv", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::keyValueParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_quoted", {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::quotedParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_between", {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::betweenParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_alphanumeric",
        {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::alphanumericParseBuilder});

    // KVDB helpers
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_lookup", {schemf::runtimeValidation(), builders::getOpBuilderKVDBGet(deps.kvdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_lookup_merge",
        {schemf::STypeToken::create(schemf::Type::OBJECT), builders::getOpBuilderKVDBGetMerge(deps.kvdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "in_kvdb", {schemf::runtimeValidation(), builders::getOpBuilderKVDBMatch(deps.kvdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "not_in_kvdb", {schemf::runtimeValidation(), builders::getOpBuilderKVDBNotMatch(deps.kvdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_lookup_append", {schemf::runtimeValidation(), builders::getOpBuilderKVDBGetArray(deps.kvdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_decode_bitmask",
        {schemf::runtimeValidation(), builders::getOpBuilderHelperKVDBDecodeBitmask(deps.kvdbManager)});

    // Windows helpers
    // registry->template add<builders::OpBuilderEntry>(
    //     "windows_sid_list_desc",
    //     {schemf::JTypeToken::create(json::Json::Type::String, true),
    //      builders::getWindowsSidListDescHelperBuilder(deps.kvdbManager, deps.kvdbScopeName)});
}

/**
 * @brief Register all stage builders in the registry.
 *
 * @tparam Registry Registry type
 * @param registry Registry instance
 * @param deps Builders dependencies
 */
template<typename Registry>
void registerStageBuilders(const std::shared_ptr<Registry>& registry, const BuilderDeps& deps)
{
    registry->template add<builders::StageBuilder>(syntax::asset::CHECK_KEY, builders::checkBuilder);
    registry->template add<builders::StageBuilder>(syntax::asset::MAP_KEY, builders::mapBuilder);
    registry->template add<builders::StageBuilder>(syntax::asset::NORMALIZE_KEY, builders::normalizeBuilder);
    registry->template add<builders::StageBuilder>(syntax::asset::PARSE_KEY,
                                                   builders::getParseBuilder(deps.logpar, deps.logparDebugLvl));
    registry->template add<builders::StageBuilder>(syntax::asset::OUTPUTS_KEY, builders::outputsBuilder);
    registry->template add<builders::StageBuilder>(syntax::asset::FIRST_OF_KEY, builders::firstOfBuilder);
    registry->template add<builders::StageBuilder>(
        syntax::asset::FILE_OUTPUT_KEY, builders::getFileOutputBuilder(deps.logManager, deps.fileOutputConfig));
    registry->template add<builders::StageBuilder>(syntax::asset::INDEXER_OUTPUT_KEY,
                                                   builders::getIndexerOutputBuilder(deps.iConnector));
}

/**
 * @brief Register all enrichment builders in the registry.
 *
 * @tparam Registry
 * @param registry Registry instance
 * @param deps Builders dependencies for enrichment builders
 * @param store Store instance to read enrichment builder configurations, not stored in the registry due to potential
 * circular dependencies
 */
template<typename Registry>
void registerEnrichmentBuilders(const std::shared_ptr<Registry>& registry,
                                const BuilderDeps& deps,
                                const std::shared_ptr<::store::IStore>& store)
{

    const auto getConfFn = [&](const base::Name& name, std::string_view builderName) -> json::Json
    {
        auto doc = store->readDoc(name);
        if (base::isError(doc))
        {
            throw std::runtime_error("Failed to register enrichment builder '" + std::string(builderName)
                                     + "': unable to read configuration: " + base::getError(doc).message);
        }
        return base::getResponse(doc);
    };

    registry->template add<builders::EnrichmentBuilder>(
        "geo",
        builders::enrichment::getGeoEnrichmentBuilder(deps.geoManager, getConfFn(STORE_GEO_CONFIG_DOC_NAME, "geo")));

    // IOC enrichment builders - dynamically registered from ioc::kvdb::details::IOC_TYPE_TABLE
    const auto iocConfig = getConfFn(STORE_IOC_CONFIG_DOC_NAME, "ioc");
    for (const auto& iocTypeInfo : ioc::kvdb::details::IOC_TYPE_TABLE)
    {
        registry->template add<builders::EnrichmentBuilder>(
            std::string(iocTypeInfo.typeKey),
            builders::enrichment::getIocEnrichmentBuilder(deps.kvdbIocManager, iocConfig, iocTypeInfo.typeKey));
    }
}

} // namespace builder::detail

#endif // BUILDER2_REGISTER_HPP

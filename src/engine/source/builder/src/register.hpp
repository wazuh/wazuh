#ifndef _BUILDER2_REGISTER_HPP
#define _BUILDER2_REGISTER_HPP

#include <memory>

#include "builder.hpp"
#include "iregistry.hpp"
#include "syntax.hpp"

// Filter builders
#include "builders/opfilter/exists.hpp"
#include "builders/opfilter/filter.hpp"
#include "builders/opfilter/opBuilderHelperFilter.hpp"

// Map builders
#include "builders/opmap/activeResponse.hpp"
#include "builders/opmap/map.hpp"
#include "builders/opmap/mmdb.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/opmap/upgradeConfirmation.hpp"
#include "builders/opmap/wdb.hpp"

// Transform builders
#include "builders/opmap/kvdb.hpp"
#include "builders/optransform/array.hpp"
#include "builders/optransform/hlp.hpp"
#include "builders/optransform/sca.hpp"
#include "builders/optransform/windows.hpp"

// Stage builders
#include "builders/stage/check.hpp"
#include "builders/stage/fileOutput.hpp"
#include "builders/stage/indexerOutput.hpp"
#include "builders/stage/map.hpp"
#include "builders/stage/normalize.hpp"
#include "builders/stage/outputs.hpp"
#include "builders/stage/parse.hpp"

namespace builder::detail
{

/**
 * @brief Register all operation (helper) builders in the registry.
 *
 * @tparam Registry Registry type
 * @param registry Registry instance
 * @param deps Builders dependencies
 */
template<typename Registry>
void registerOpBuilders(const std::shared_ptr<Registry>& registry, const BuilderDeps& deps)
{
    // Filter builders
    registry->template add<builders::OpBuilderEntry>(
        "filter", {builders::opfilter::filterValidator(), builders::opfilter::filterBuilder});
    registry->template add<builders::OpBuilderEntry>("exists",
                                                     {schemf::runtimeValidation(), builders::opfilter::existsBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "not_exists", {schemf::runtimeValidation(), builders::opfilter::notExistsBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "array_contains", {schemf::isArrayToken(), builders::opfilter::opBuilderHelperContains});
    registry->template add<builders::OpBuilderEntry>(
        "array_contains_any", {schemf::isArrayToken(), builders::opfilter::opBuilderHelperContainsAny});
    registry->template add<builders::OpBuilderEntry>(
        "array_not_contains", {schemf::isArrayToken(), builders::opfilter::opBuilderHelperNotContains});
    registry->template add<builders::OpBuilderEntry>(
        "array_not_contains_any", {schemf::isArrayToken(), builders::opfilter::opBuilderHelperNotContainsAny});
    registry->template add<builders::OpBuilderEntry>(
        "int_equal",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntEqual});
    registry->template add<builders::OpBuilderEntry>(
        "int_greater",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntGreaterThan});
    registry->template add<builders::OpBuilderEntry>(
        "int_greater_or_equal",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntGreaterThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "int_less",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntLessThan});
    registry->template add<builders::OpBuilderEntry>(
        "int_less_or_equal",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntLessThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "int_not_equal",
        {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntNotEqual});
    registry->template add<builders::OpBuilderEntry>(
        "ip_cidr_match", {schemf::STypeToken::create(schemf::Type::IP), builders::opfilter::opBuilderHelperIPCIDR});
    registry->template add<builders::OpBuilderEntry>(
        "is_public_ip", {schemf::STypeToken::create(schemf::Type::IP), builders::opfilter::opBuilderHelperPublicIP});
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
        "binary_and",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperBinaryAnd});
    registry->template add<builders::OpBuilderEntry>(
        "regex_match",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperRegexMatch});
    registry->template add<builders::OpBuilderEntry>(
        "regex_not_match",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperRegexNotMatch});
    registry->template add<builders::OpBuilderEntry>(
        "string_equal",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_greater",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringGreaterThan});
    registry->template add<builders::OpBuilderEntry>("string_greater_or_equal",
                                                     {schemf::JTypeToken::create(json::Json::Type::String),
                                                      builders::opfilter::opBuilderHelperStringGreaterThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_less",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringLessThan});
    registry->template add<builders::OpBuilderEntry>(
        "string_less_or_equal",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringLessThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_not_equal",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringNotEqual});
    registry->template add<builders::OpBuilderEntry>(
        "starts_with",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringStarts});
    registry->template add<builders::OpBuilderEntry>(
        "contains",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperStringContains});
    registry->template add<builders::OpBuilderEntry>(
        "match_value", {schemf::runtimeValidation(), builders::opfilter::opBuilderHelperMatchValue});
    registry->template add<builders::OpBuilderEntry>(
        "exists_key_in",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opfilter::opBuilderHelperMatchKey});

    // Map builders
    registry->template add<builders::OpBuilderEntry>("map",
                                                     {builders::opmap::mapValidator(), builders::opmap::mapBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "to_string", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperNumberToString});
    registry->template add<builders::OpBuilderEntry>(
        "int_calculate", {schemf::JTypeToken::create(json::Json::Type::Number), builders::opBuilderHelperIntCalc});
    registry->template add<builders::OpBuilderEntry>(
        "regex_extract", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperRegexExtract});
    // Map helpers: Hash functions
    registry->template add<builders::OpBuilderEntry>(
        "sha1", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperHashSHA1});
    registry->template add<builders::OpBuilderEntry>(
        "hex_to_number", {schemf::JTypeToken::create(json::Json::Type::Number), builders::opBuilderHelperHexToNumber});
    registry->template add<builders::OpBuilderEntry>(
        "ip_version",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperIPVersionFromIPStr});
    registry->template add<builders::OpBuilderEntry>(
        "join", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringFromArray});
    registry->template add<builders::OpBuilderEntry>(
        "decode_base16",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringFromHexa});
    registry->template add<builders::OpBuilderEntry>(
        "downcase", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringLO});
    registry->template add<builders::OpBuilderEntry>(
        "upcase", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringUP});
    // Map helpers: Time functions
    registry->template add<builders::OpBuilderEntry>(
        "system_epoch",
        {schemf::STypeToken::create(schemf::Type::DATE_NANOS), builders::opBuilderHelperEpochTimeFromSystem});
    registry->template add<builders::OpBuilderEntry>(
        "date_from_epoch",
        {schemf::STypeToken::create(schemf::Type::DATE), builders::opBuilderHelperDateFromEpochTime});

    // Transform builders
    registry->template add<builders::OpBuilderEntry>(
        "array_append_unique", {schemf::isArrayToken(), builders::optransform::getArrayAppendBuilder(true, false)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append", {schemf::isArrayToken(), builders::optransform::getArrayAppendBuilder(false, false)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append_unique_any", {schemf::isArrayToken(), builders::optransform::getArrayAppendBuilder(true, true)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append_any", {schemf::isArrayToken(), builders::optransform::getArrayAppendBuilder(false, true)});
    // Transform helpers: Event Field functions
    registry->template add<builders::OpBuilderEntry>(
        "delete", {schemf::runtimeValidation(), builders::opBuilderHelperDeleteField});
    // TODO: this builders should check that the field is an array or an object
    registry->template add<builders::OpBuilderEntry>("merge",
                                                     {schemf::runtimeValidation(), builders::opBuilderHelperMerge});
    registry->template add<builders::OpBuilderEntry>(
        "merge_recursive",
        {schemf::STypeToken::create(schemf::Type::OBJECT), builders::opBuilderHelperMergeRecursively});
    // helperRegistry->registerBuilder(builders::opBuilderHelperRenameField, "rename");
    registry->template add<builders::OpBuilderEntry>(
        "rename", {schemf::runtimeValidation(), builders::opBuilderHelperRenameField});
    // Transform helpers: String functions
    registry->template add<builders::OpBuilderEntry>(
        "split",
        {schemf::JTypeToken::create(json::Json::Type::String, true), builders::opBuilderHelperAppendSplitString});
    registry->template add<builders::OpBuilderEntry>(
        "concat", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringConcat()});
    registry->template add<builders::OpBuilderEntry>(
        "concat_any",
        {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringConcat(true)});
    registry->template add<builders::OpBuilderEntry>(
        "replace", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringReplace});
    registry->template add<builders::OpBuilderEntry>(
        "trim", {schemf::JTypeToken::create(json::Json::Type::String), builders::opBuilderHelperStringTrim});
    // Transform helpers: Definition functions
    registry->template add<builders::OpBuilderEntry>(
        "get_key_in", {schemf::runtimeValidation(), builders::opBuilderHelperGetValue}); // TODO: add validation
    registry->template add<builders::OpBuilderEntry>(
        "merge_key_in", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::opBuilderHelperMergeValue});
    // Transform helpers: MMDB functions
    registry->template add<builders::OpBuilderEntry>(
        "geoip",
        {schemf::STypeToken::create(schemf::Type::OBJECT), builders::mmdb::getMMDBGeoBuilder(deps.geoManager)});
    registry->template add<builders::OpBuilderEntry>(
        "as", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::mmdb::getMMDBASNBuilder(deps.geoManager)});
    // Global event helpers
    registry->template add<builders::OpBuilderEntry>(
        "erase_custom_fields", {schemf::runtimeValidation(), builders::opBuilderHelperEraseCustomFields});
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
        "parse_double", {schemf::STypeToken::create(schemf::Type::DOUBLE), builders::optransform::doubleParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_binary", {schemf::STypeToken::create(schemf::Type::BINARY), builders::optransform::binaryParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_date", {schemf::STypeToken::create(schemf::Type::DATE), builders::optransform::dateParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_ip", {schemf::STypeToken::create(schemf::Type::IP), builders::optransform::ipParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_uri", {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::uriParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_useragent",
        {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::userAgentParseBuilder});
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
        "parse_key_value",
        {schemf::STypeToken::create(schemf::Type::OBJECT), builders::optransform::keyValueParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_quoted", {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::quotedParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_between", {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::betweenParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_alphanumeric",
        {schemf::STypeToken::create(schemf::Type::TEXT), builders::optransform::alphanumericParseBuilder});

    // KVDB builders
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_delete",
        {schemf::runtimeValidation(), builders::getOpBuilderKVDBDelete(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_get", {schemf::runtimeValidation(), builders::getOpBuilderKVDBGet(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_get_merge",
        {schemf::runtimeValidation(), builders::getOpBuilderKVDBGetMerge(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_match",
        {schemf::runtimeValidation(), builders::getOpBuilderKVDBMatch(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_not_match",
        {schemf::runtimeValidation(), builders::getOpBuilderKVDBNotMatch(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_set", {schemf::runtimeValidation(), builders::getOpBuilderKVDBSet(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_get_array",
        {schemf::runtimeValidation(), builders::getOpBuilderKVDBGetArray(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_decode_bitmask",
        {schemf::runtimeValidation(),
         builders::getOpBuilderHelperKVDBDecodeBitmask(deps.kvdbManager, deps.kvdbScopeName)});

    // Active Response builders
    registry->template add<builders::OpBuilderEntry>(
        "active_response_send", {schemf::runtimeValidation(), builders::getOpBuilderSendAr(deps.sockFactory)});
    // TODO: this builder is not used in the ruleset
    // registry->template add<builders::OpBuilderEntry>("active_response_create",
    //                                                  {schemf::runtimeValidation(), builders::CreateARBuilder});

    // Upgrade confirmation builder
    registry->template add<builders::OpBuilderEntry>(
        "send_upgrade_confirmation",
        {schemf::JTypeToken::create(json::Json::Type::Boolean),
         builders::opmap::getUpgradeConfirmationBUilder(deps.sockFactory)});

    // WDB builders
    registry->template add<builders::OpBuilderEntry>(
        "wdb_update", {schemf::runtimeValidation(), builders::opmap::getWdbUpdateBuilder(deps.wdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "wdb_query", {schemf::runtimeValidation(), builders::opmap::getWdbQueryBuilder(deps.wdbManager)});

    // SCA builders
    registry->template add<builders::OpBuilderEntry>(
        "sca_decoder",
        {schemf::runtimeValidation(), builders::optransform::getBuilderSCAdecoder(deps.wdbManager, deps.sockFactory)});

    // Windows builders
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
    registry->template add<builders::StageBuilder>(syntax::asset::FILE_OUTPUT_KEY, builders::fileOutputBuilder);
    registry->template add<builders::StageBuilder>(syntax::asset::INDEXER_OUTPUT_KEY,
                                                   builders::getIndexerOutputBuilder(deps.iConnector));
}

} // namespace builder::detail

#endif // _BUILDER2_REGISTER_HPP

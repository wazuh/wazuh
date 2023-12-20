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
#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/opmap/upgradeConfirmation.hpp"
#include "builders/opmap/wdb.hpp"

// Transform builders
#include "builders/opmap/kvdb.hpp"
#include "builders/optransform/array.hpp"
#include "builders/optransform/hlp.hpp"
#include "builders/optransform/netinfoAddress.hpp"
#include "builders/optransform/sca.hpp"
#include "builders/optransform/windows.hpp"

// Stage builders
#include "builders/stage/check.hpp"
#include "builders/stage/fileOutput.hpp"
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
                                                     {schemval::ValidationToken {}, builders::opfilter::existsBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "not_exists", {schemval::ValidationToken {}, builders::opfilter::notExistsBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "array_contains", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperContainsString});
    registry->template add<builders::OpBuilderEntry>(
        "array_not_contains", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperNotContainsString});
    registry->template add<builders::OpBuilderEntry>(
        "int_equal",
        {schemval::ValidationToken {json::Json::Type::Number}, builders::opfilter::opBuilderHelperIntEqual});
    registry->template add<builders::OpBuilderEntry>(
        "int_greater",
        {schemval::ValidationToken {json::Json::Type::Number}, builders::opfilter::opBuilderHelperIntGreaterThan});
    registry->template add<builders::OpBuilderEntry>(
        "int_greater_or_equal",
        {schemval::ValidationToken {json::Json::Type::Number}, builders::opfilter::opBuilderHelperIntGreaterThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "int_less",
        {schemval::ValidationToken {json::Json::Type::Number}, builders::opfilter::opBuilderHelperIntLessThan});
    registry->template add<builders::OpBuilderEntry>(
        "int_less_or_equal",
        {schemval::ValidationToken {json::Json::Type::Number}, builders::opfilter::opBuilderHelperIntLessThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "int_not_equal",
        {schemval::ValidationToken {json::Json::Type::Number}, builders::opfilter::opBuilderHelperIntNotEqual});
    registry->template add<builders::OpBuilderEntry>(
        "ip_cidr_match", {schemval::ValidationToken {schemf::Type::IP}, builders::opfilter::opBuilderHelperIPCIDR});
    registry->template add<builders::OpBuilderEntry>(
        "is_array", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsArray});
    registry->template add<builders::OpBuilderEntry>(
        "is_boolean", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsBool});
    registry->template add<builders::OpBuilderEntry>(
        "is_false", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsFalse});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_array", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNotArray});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_boolean", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNotBool});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_null", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNotNull});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_number", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNotNumber});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_object", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNotObject});
    registry->template add<builders::OpBuilderEntry>(
        "is_not_string", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNotString});
    registry->template add<builders::OpBuilderEntry>(
        "is_null", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNull});
    registry->template add<builders::OpBuilderEntry>(
        "is_number", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsNumber});
    registry->template add<builders::OpBuilderEntry>(
        "is_object", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsObject});
    registry->template add<builders::OpBuilderEntry>(
        "is_string", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsString});
    registry->template add<builders::OpBuilderEntry>(
        "is_true", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperIsTrue});
    registry->template add<builders::OpBuilderEntry>(
        "regex_match",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperRegexMatch});
    registry->template add<builders::OpBuilderEntry>(
        "regex_not_match",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperRegexNotMatch});
    registry->template add<builders::OpBuilderEntry>(
        "string_equal",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_greater",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringGreaterThan});
    registry->template add<builders::OpBuilderEntry>("string_greater_or_equal",
                                                     {schemval::ValidationToken {json::Json::Type::String},
                                                      builders::opfilter::opBuilderHelperStringGreaterThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_less",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringLessThan});
    registry->template add<builders::OpBuilderEntry>(
        "string_less_or_equal",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringLessThanEqual});
    registry->template add<builders::OpBuilderEntry>(
        "string_not_equal",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringNotEqual});
    registry->template add<builders::OpBuilderEntry>(
        "starts_with",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringStarts});
    registry->template add<builders::OpBuilderEntry>(
        "contains",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperStringContains});
    registry->template add<builders::OpBuilderEntry>(
        "match_value", {schemval::ValidationToken {}, builders::opfilter::opBuilderHelperMatchValue});
    registry->template add<builders::OpBuilderEntry>(
        "match_key",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opfilter::opBuilderHelperMatchKey});

    // Map builders
    registry->template add<builders::OpBuilderEntry>("map",
                                                     {builders::opmap::mapValidator(), builders::opmap::mapBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "int_calculate", {schemval::ValidationToken {json::Json::Type::Number}, builders::opBuilderHelperIntCalc});
    registry->template add<builders::OpBuilderEntry>(
        "regex_extract", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperRegexExtract});
    // Map helpers: Hash functions
    registry->template add<builders::OpBuilderEntry>(
        "sha1", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperHashSHA1});
    registry->template add<builders::OpBuilderEntry>(
        "hex_to_number", {schemval::ValidationToken {json::Json::Type::Number}, builders::opBuilderHelperHexToNumber});
    registry->template add<builders::OpBuilderEntry>(
        "ip_version",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperIPVersionFromIPStr});
    registry->template add<builders::OpBuilderEntry>(
        "join", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringFromArray});
    registry->template add<builders::OpBuilderEntry>(
        "decode_base16",
        {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringFromHexa});
    registry->template add<builders::OpBuilderEntry>(
        "downcase", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringLO});
    registry->template add<builders::OpBuilderEntry>(
        "upcase", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringUP});
    // Map helpers: Time functions
    registry->template add<builders::OpBuilderEntry>(
        "system_epoch",
        {schemval::ValidationToken {schemf::Type::DATE_NANOS}, builders::opBuilderHelperEpochTimeFromSystem});
    registry->template add<builders::OpBuilderEntry>(
        "date_from_epoch",
        {schemval::ValidationToken {schemf::Type::DATE}, builders::opBuilderHelperDateFromEpochTime});

    // Transform builders
    registry->template add<builders::OpBuilderEntry>(
        "array_append_unique", {schemval::ValidationToken {}, builders::optransform::getArrayAppendBuilder(true)});
    registry->template add<builders::OpBuilderEntry>(
        "array_append", {schemval::ValidationToken {}, builders::optransform::getArrayAppendBuilder(false)});
    // Transform helpers: Event Field functions
    registry->template add<builders::OpBuilderEntry>(
        "delete", {schemval::ValidationToken {}, builders::opBuilderHelperDeleteField});
    // TODO: this builders should check that the field is an array or an object
    registry->template add<builders::OpBuilderEntry>("merge",
                                                     {schemval::ValidationToken {}, builders::opBuilderHelperMerge});
    registry->template add<builders::OpBuilderEntry>(
        "merge_recursive",
        {schemval::ValidationToken {schemf::Type::OBJECT}, builders::opBuilderHelperMergeRecursively});
    // helperRegistry->registerBuilder(builders::opBuilderHelperRenameField, "rename");
    registry->template add<builders::OpBuilderEntry>(
        "rename", {schemval::ValidationToken {}, builders::opBuilderHelperRenameField});
    // Transform helpers: String functions
    registry->template add<builders::OpBuilderEntry>(
        "split",
        {schemval::ValidationToken {json::Json::Type::String, true}, builders::opBuilderHelperAppendSplitString});
    registry->template add<builders::OpBuilderEntry>(
        "concat", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringConcat});
    registry->template add<builders::OpBuilderEntry>(
        "replace", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringReplace});
    registry->template add<builders::OpBuilderEntry>(
        "trim", {schemval::ValidationToken {json::Json::Type::String}, builders::opBuilderHelperStringTrim});
    // Transform helpers: Definition functions
    registry->template add<builders::OpBuilderEntry>(
        "get_value", {schemval::ValidationToken {}, builders::opBuilderHelperGetValue}); // TODO: add validation
    registry->template add<builders::OpBuilderEntry>(
        "merge_value", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::opBuilderHelperMergeValue});
    // Global event helpers
    registry->template add<builders::OpBuilderEntry>(
        "erase_custom_fields", {schemval::ValidationToken {}, builders::opBuilderHelperEraseCustomFields});
    // HLP Parser helpers
    registry->template add<builders::OpBuilderEntry>(
        "parse_bool", {schemval::ValidationToken {schemf::Type::TEXT}, builders::optransform::boolParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_byte", {schemval::ValidationToken {schemf::Type::BYTE}, builders::optransform::byteParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_long", {schemval::ValidationToken {schemf::Type::LONG}, builders::optransform::longParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_float", {schemval::ValidationToken {schemf::Type::FLOAT}, builders::optransform::floatParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_double", {schemval::ValidationToken {schemf::Type::DOUBLE}, builders::optransform::doubleParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_binary", {schemval::ValidationToken {schemf::Type::BINARY}, builders::optransform::binaryParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_date", {schemval::ValidationToken {schemf::Type::DATE}, builders::optransform::dateParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_ip", {schemval::ValidationToken {schemf::Type::IP}, builders::optransform::ipParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_uri", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::uriParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_useragent",
        {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::userAgentParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_fqdn", {schemval::ValidationToken {schemf::Type::TEXT}, builders::optransform::fqdnParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_file", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::filePathParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_json", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::jsonParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_xml", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::xmlParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_csv", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::csvParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_dsv", {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::dsvParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_key_value",
        {schemval::ValidationToken {schemf::Type::OBJECT}, builders::optransform::keyValueParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_quoted", {schemval::ValidationToken {schemf::Type::TEXT}, builders::optransform::quotedParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_between", {schemval::ValidationToken {schemf::Type::TEXT}, builders::optransform::betweenParseBuilder});
    registry->template add<builders::OpBuilderEntry>(
        "parse_alphanumeric",
        {schemval::ValidationToken {schemf::Type::TEXT}, builders::optransform::alphanumericParseBuilder});

    // KVDB builders
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_delete",
        {schemval::ValidationToken {}, builders::getOpBuilderKVDBDelete(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_get",
        {schemval::ValidationToken {}, builders::getOpBuilderKVDBGet(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_get_merge",
        {schemval::ValidationToken {}, builders::getOpBuilderKVDBGetMerge(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_match",
        {schemval::ValidationToken {}, builders::getOpBuilderKVDBMatch(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_not_match",
        {schemval::ValidationToken {}, builders::getOpBuilderKVDBNotMatch(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_set",
        {schemval::ValidationToken {}, builders::getOpBuilderKVDBSet(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_get_array",
        {schemval::ValidationToken {json::Json::Type::Array},
         builders::getOpBuilderKVDBGetArray(deps.kvdbManager, deps.kvdbScopeName)});
    registry->template add<builders::OpBuilderEntry>(
        "kvdb_decode_bitmask",
        {schemval::ValidationToken {json::Json::Type::Array},
         builders::getOpBuilderHelperKVDBDecodeBitmask(deps.kvdbManager, deps.kvdbScopeName)});

    // Active Response builders
    registry->template add<builders::OpBuilderEntry>(
        "active_response_send", {schemval::ValidationToken {}, builders::getOpBuilderSendAr(deps.sockFactory)});
    registry->template add<builders::OpBuilderEntry>("active_response_create",
                                                     {schemval::ValidationToken {}, builders::CreateARBuilder});

    // Upgrade confirmation builder
    registry->template add<builders::OpBuilderEntry>(
        "send_upgrade_confirmation",
        {schemval::ValidationToken {json::Json::Type::Boolean},
         builders::opmap::getUpgradeConfirmationBUilder(deps.sockFactory)});

    // Netinfo address builder
    registry->template add<builders::OpBuilderEntry>(
        "sysc_ni_save_ipv4",
        {schemval::ValidationToken {}, builders::optransform::getSaveNetInfoIPv4Builder(deps.wdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "sysc_ni_save_ipv6",
        {schemval::ValidationToken {}, builders::optransform::getSaveNetInfoIPv6Builder(deps.wdbManager)});

    // WDB builders
    registry->template add<builders::OpBuilderEntry>(
        "wdb_update", {schemval::ValidationToken {}, builders::opmap::getWdbUpdateBuilder(deps.wdbManager)});
    registry->template add<builders::OpBuilderEntry>(
        "wdb_query", {schemval::ValidationToken {}, builders::opmap::getWdbQueryBuilder(deps.wdbManager)});

    // SCA builders
    registry->template add<builders::OpBuilderEntry>(
        "sca_decoder",
        {schemval::ValidationToken {}, builders::optransform::getBuilderSCAdecoder(deps.wdbManager, deps.sockFactory)});

    // Windows builders
    registry->template add<builders::OpBuilderEntry>(
        "windows_sid_list_desc",
        {schemval::ValidationToken {json::Json::Type::String, true},
         builders::getWindowsSidListDescHelperBuilder(deps.kvdbManager, deps.kvdbScopeName)});
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
}

} // namespace builder::detail

#endif // _BUILDER2_REGISTER_HPP

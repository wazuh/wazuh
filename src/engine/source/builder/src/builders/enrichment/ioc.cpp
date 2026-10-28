// SPDX-License-Identifier: AGPL-3.0-or-later
#include <fmt/format.h>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>

#include <iockvdb/helpers.hpp>
#include <iockvdb/iManager.hpp>

#include "enrichment.hpp"

namespace builder::builders::enrichment
{

namespace
{

constexpr std::string_view IOC_ENRICHMENT_TARGET_PATH {"/wazuh/threat/enrichments"};
constexpr std::string_view INDICATOR_CONFIDENCE_PATH {"/indicator/confidence"}; ///< Relative to one enrichment entry

constexpr auto FMT_IOC_MATCH_TRACE = "IOC({}) -> Success: IOC match found for field '{}' with key '{}'";
constexpr auto FMT_IOC_NOT_FOUND_TRACE = "IOC({}) -> Failure: IOC key '{}' not found for field '{}'";
constexpr auto FMT_IOC_SOURCE_MISSING_TRACE = "IOC({}) -> Failure: Source field(s) not found for '{}'";

struct IocSourcePath
{
    std::string path;              // String form (for exists/getIntAsInt64/getDouble that take string_view)
    json::PointerPath pp;          // Pre-built pointer (for getString)
    json::PointerPath ppFirstElem; // Pre-built pointer to first array element path + "/0"

    explicit IocSourcePath(std::string pathStr)
        : path(std::move(pathStr))
        , pp(path)
        , ppFirstElem(path + "/0")
    {
    }
};

struct IocMappingConfig
{
    std::string iocType;
    std::string dbName;
    std::string sourceFields;
    std::vector<IocSourcePath> sourcePaths;
    std::optional<std::string> commonParentPath;
};

std::string getTopLevelParentPath(std::string_view jsonPointerPath)
{
    if (jsonPointerPath.empty() || jsonPointerPath.front() != '/')
    {
        return {};
    }

    const auto nextSlashPos = jsonPointerPath.find('/', 1);
    if (nextSlashPos == std::string_view::npos)
    {
        return std::string(jsonPointerPath);
    }

    return std::string(jsonPointerPath.substr(0, nextSlashPos));
}

std::optional<std::string> readFieldAsString(base::Event event, const IocSourcePath& source)
{
    // Try to read as string first, can be a string or an array of strings
    // In the latter case, we take the first element
    std::string stringValue;
    if (event->getString(stringValue, source.pp) == json::RetGet::Success
        || event->getString(stringValue, source.ppFirstElem) == json::RetGet::Success)
    {
        return stringValue;
    }

    // If not a string, try to read as int64 and convert
    auto intValue = event->getIntAsInt64(source.path);
    if (intValue.has_value())
    {
        return std::to_string(*intValue);
    }

    // Try to read as double and convert
    auto doubleValue = event->getDouble(source.path);
    if (doubleValue.has_value())
    {
        return std::to_string(*doubleValue);
    }

    return std::nullopt;
}

/**
 * @brief Build one enrichment entry (WCS `wazuh.threat.enrichments`) for one indicator document.
 *
 * WCS maps `indicator.confidence` as a keyword while the CTI documents carry it as a number, so a numeric
 * confidence is written as its string form.
 */
json::Json makeEnrichmentEntry(const json::Json& indicator, const std::string& matchedField)
{
    json::Json entry;
    entry.setObject();
    entry.set("/indicator", indicator);

    if (entry.isNumber(INDICATOR_CONFIDENCE_PATH))
    {
        if (const auto asInt = entry.getIntAsInt64(INDICATOR_CONFIDENCE_PATH); asInt.has_value())
        {
            entry.setString(std::to_string(*asInt), INDICATOR_CONFIDENCE_PATH);
        }
        else if (const auto asNumber = entry.getNumberAsDouble(INDICATOR_CONFIDENCE_PATH); asNumber.has_value())
        {
            entry.setString(fmt::format("{}", *asNumber), INDICATOR_CONFIDENCE_PATH);
        }
    }

    entry.setObject("/matched");
    entry.setString(matchedField, "/matched/field");
    return entry;
}

std::optional<std::string> buildLookupKey(base::Event event, const IocMappingConfig& config)
{
    if (config.commonParentPath.has_value() && !event->exists(*config.commonParentPath))
    {
        return std::nullopt;
    }

    std::vector<std::string> parts;
    parts.reserve(config.sourcePaths.size());

    for (const auto& sourcePath : config.sourcePaths)
    {
        auto part = readFieldAsString(event, sourcePath);
        if (!part.has_value() || part->empty())
        {
            return std::nullopt;
        }

        parts.push_back(*part);
    }

    if (parts.empty())
    {
        return std::nullopt;
    }

    if (parts.size() == 1)
    {
        // Normalize to lowercase for case-insensitive matching
        return base::utils::string::toLowerCase(parts.front());
    }

    std::string lookupKey;
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        lookupKey += parts[i];
        if (i + 1 < parts.size())
        {
            lookupKey += ':';
        }
    }

    // Normalize to lowercase for case-insensitive matching
    return base::utils::string::toLowerCase(lookupKey);
}

std::vector<IocMappingConfig> loadIocMappingConfigs(const json::Json& config, std::string_view iocType)
{
    if (!config.isObject())
    {
        throw std::runtime_error("IOC mapping configuration must be a JSON object");
    }

    // Get IOC type info using helpers
    const auto typeInfo = ioc::kvdb::details::findIOCTypeInfo(iocType);
    if (!typeInfo.has_value())
    {
        throw std::runtime_error(fmt::format("Unknown IOC type '{}'", iocType));
    }

    const std::string dbName {typeInfo->dbName};
    const auto iocTypeEnum = typeInfo->type;

    // Lambda to process simple string array sources (used by hash and URL types)
    auto processSimpleStringSources = [&](std::string_view sourcesPath) -> std::vector<IocMappingConfig>
    {
        const auto sourcesOpt = config.getArray(sourcesPath);
        if (!sourcesOpt.has_value())
        {
            throw std::runtime_error(
                fmt::format("IOC mapping for '{}' requires 'sources' array at '{}'", iocType, sourcesPath));
        }

        std::vector<IocMappingConfig> configs;
        for (const auto& sourceField : *sourcesOpt)
        {
            if (!sourceField.isString())
            {
                throw std::runtime_error(fmt::format("Source field must be a string for IOC type '{}'", iocType));
            }

            std::string fieldStr;
            sourceField.getString(fieldStr);
            IocMappingConfig cfg;
            cfg.iocType = std::string(iocType);
            cfg.dbName = dbName;
            cfg.sourceFields = fieldStr;

            const auto sourcePath = json::Json::formatJsonPath(fieldStr);
            cfg.sourcePaths.emplace_back(sourcePath);
            cfg.commonParentPath = getTopLevelParentPath(sourcePath);

            configs.push_back(std::move(cfg));
        }
        return configs;
    };

    // Handle connection type: sources are objects with ip_field and port_field
    if (iocTypeEnum == ioc::kvdb::details::IOCType::CONNECTION)
    {
        const auto sourcesOpt = config.getArray("/connection/sources");
        if (!sourcesOpt.has_value())
        {
            throw std::runtime_error("IOC mapping for 'connection' must have a 'sources' array");
        }

        std::vector<IocMappingConfig> configs;
        for (const auto& sourceObj : *sourcesOpt)
        {
            std::string ipFieldStr;
            std::string portFieldStr;
            const auto ipFieldRet = sourceObj.getString(ipFieldStr, "/ip_field");
            const auto portFieldRet = sourceObj.getString(portFieldStr, "/port_field");

            if (ipFieldRet != json::RetGet::Success || portFieldRet != json::RetGet::Success)
            {
                throw std::runtime_error("Connection source must have 'ip_field' and 'port_field'");
            }

            IocMappingConfig cfg;
            cfg.iocType = std::string(iocType);
            cfg.dbName = dbName;
            cfg.sourceFields = fmt::format("{}, {}", ipFieldStr, portFieldStr);

            // Convert dot notation to JSON pointer
            const auto ipPath = json::Json::formatJsonPath(ipFieldStr);
            const auto portPath = json::Json::formatJsonPath(portFieldStr);

            cfg.sourcePaths.emplace_back(ipPath);
            cfg.sourcePaths.emplace_back(portPath);

            // Check for common parent
            const auto ipParent = getTopLevelParentPath(ipPath);
            const auto portParent = getTopLevelParentPath(portPath);
            if (ipParent == portParent && !ipParent.empty())
            {
                cfg.commonParentPath = ipParent;
            }

            configs.push_back(std::move(cfg));
        }
        return configs;
    }

    // All other types (hash_*, url-*) use the typeKey directly as the config key
    const auto sourcesPath = fmt::format("/{}/sources", typeInfo->typeKey);
    return processSimpleStringSources(sourcesPath);
}

base::Expression getEachIocEnrichTerm(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbIocManager,
                                      const IocMappingConfig& config,
                                      bool isTestMode,
                                      const std::shared_ptr<bool>& matchFound)
{
    auto opFn = [kvdbIocManager, config, isTestMode, matchFound](base::Event event) -> base::result::Result<base::Event>
    {
        const auto keyOpt = buildLookupKey(event, config);
        if (!keyOpt.has_value())
        {
            const auto traceMsg = isTestMode
                                      ? fmt::format(FMT_IOC_SOURCE_MISSING_TRACE, config.iocType, config.sourceFields)
                                      : std::string {};
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }

        const auto& lookupKey = *keyOpt;
        auto iocValue = kvdbIocManager->get(config.dbName, lookupKey);
        if (!iocValue.has_value())
        {
            const auto traceMsg =
                isTestMode ? fmt::format(FMT_IOC_NOT_FOUND_TRACE, config.iocType, lookupKey, config.sourceFields)
                           : std::string {};
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }

        // One enrichment entry per indicator document: several CTI documents can share a key, and the KVDB
        // then holds them as an array (WCS maps `indicator` as a single object).
        std::size_t appended = 0;
        if (iocValue->isArray())
        {
            for (const auto& indicator : iocValue->getArray().value_or(std::vector<json::Json> {}))
            {
                event->appendJson(makeEnrichmentEntry(indicator, config.sourceFields), IOC_ENRICHMENT_TARGET_PATH);
                ++appended;
            }
        }
        else
        {
            event->appendJson(makeEnrichmentEntry(*iocValue, config.sourceFields), IOC_ENRICHMENT_TARGET_PATH);
            ++appended;
        }

        if (appended == 0)
        {
            const auto traceMsg =
                isTestMode ? fmt::format(FMT_IOC_NOT_FOUND_TRACE, config.iocType, lookupKey, config.sourceFields)
                           : std::string {};
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }
        *matchFound = true;

        const auto traceMsg = isTestMode
                                  ? fmt::format(FMT_IOC_MATCH_TRACE, config.iocType, config.sourceFields, lookupKey)
                                  : std::string {};

        return base::result::makeSuccess<decltype(event)>(event, traceMsg);
    };

    return base::Term<base::EngineOp>::create("ioc_enrichment", opFn);
}

std::pair<base::Expression, std::string>
iocEnrichmentBuilder(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbIocManager,
                     const std::vector<IocMappingConfig>& mappingConfigs,
                     std::string traceableName,
                     bool isTestMode)
{
    if (!kvdbIocManager)
    {
        throw std::runtime_error("IOC enrichment requires a valid KVDB IOC manager");
    }

    // Shared flag to track if any IOC match was found
    auto matchFound = std::make_shared<bool>(false);

    std::vector<base::Expression> enrichmentTerms;
    enrichmentTerms.reserve(mappingConfigs.size());

    for (const auto& config : mappingConfigs)
    {
        enrichmentTerms.push_back(getEachIocEnrichTerm(kvdbIocManager, config, isTestMode, matchFound));
    }

    base::Expression enrichmentExpr = base::Chain::create(traceableName, enrichmentTerms);

    if (!isTestMode)
    {
        return {enrichmentExpr, traceableName};
    }

    // Only emit SUCCESS if at least one IOC match was found
    auto conditionalSuccess =
        base::Term<base::EngineOp>::create("ConditionalAccept",
                                           [matchFound](auto e) -> base::result::Result<base::Event>
                                           {
                                               if (*matchFound)
                                               {
                                                   *matchFound = false;
                                                   return base::result::makeSuccess(e, "SUCCESS");
                                               }
                                               return base::result::makeFailure(e, std::string {});
                                           });

    // Named like the traceable so the SUCCESS term publishes to its tracer (see makeTraceableSuccessExpression)
    return {base::Implication::create(traceableName, enrichmentExpr, conditionalSuccess), traceableName};
}

} // namespace

EnrichmentBuilder getIocEnrichmentBuilder(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbIocManager,
                                          const json::Json& configDoc,
                                          std::string_view iocType)
{
    const auto mappingConfigs = loadIocMappingConfigs(configDoc, iocType);
    const auto traceableName = fmt::format("enrichment/IOC/{}", iocType);

    return [kvdbIocManager, mappingConfigs, traceableName](bool isTestMode) -> std::pair<base::Expression, std::string>
    {
        return iocEnrichmentBuilder(kvdbIocManager, mappingConfigs, traceableName, isTestMode);
    };
}

} // namespace builder::builders::enrichment

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

constexpr std::string_view IOC_ENRICHMENT_TARGET_PATH {"/threat/enrichments"};

constexpr auto FMT_IOC_MATCH_TRACE = "IOC({}) -> Success: IOC match found for field '{}' with key '{}'";
constexpr auto FMT_IOC_NOT_FOUND_TRACE = "IOC({}) -> Failure: IOC key '{}' not found for field '{}'";
constexpr auto FMT_IOC_SOURCE_MISSING_TRACE = "IOC({}) -> Failure: Source field(s) not found for '{}'";

struct IocMappingConfig
{
    std::string iocType;
    std::string dbName;
    std::string sourceFields;
    std::vector<std::string> sourcePaths;
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

std::optional<std::string> readFieldAsString(base::Event event, std::string_view path)
{
    // Try to read as string first, can be a string or an array of strings
    // In the latter case, we take the first element
    auto stringValue = event->getString(path);
    if (!stringValue.has_value())
    {
        stringValue = event->getString(std::string(path) + "/0");
    }

    if (stringValue.has_value())
    {
        return stringValue;
    }

    // If not a string, try to read as int64 and convert
    auto intValue = event->getIntAsInt64(path);
    if (intValue.has_value())
    {
        return std::to_string(*intValue);
    }

    // Try to read as double and convert
    auto doubleValue = event->getDouble(path);
    if (doubleValue.has_value())
    {
        return std::to_string(*doubleValue);
    }

    return std::nullopt;
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

            const auto fieldStr = sourceField.getString().value();
            IocMappingConfig cfg;
            cfg.iocType = std::string(iocType);
            cfg.dbName = dbName;
            cfg.sourceFields = fieldStr;

            const auto sourcePath = json::Json::formatJsonPath(fieldStr);
            cfg.sourcePaths.push_back(sourcePath);
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
            const auto ipFieldOpt = sourceObj.getString("/ip_field");
            const auto portFieldOpt = sourceObj.getString("/port_field");

            if (!ipFieldOpt.has_value() || !portFieldOpt.has_value())
            {
                throw std::runtime_error("Connection source must have 'ip_field' and 'port_field'");
            }

            IocMappingConfig cfg;
            cfg.iocType = std::string(iocType);
            cfg.dbName = dbName;
            cfg.sourceFields = fmt::format("{}, {}", *ipFieldOpt, *portFieldOpt);

            // Convert dot notation to JSON pointer
            const auto ipPath = json::Json::formatJsonPath(*ipFieldOpt);
            const auto portPath = json::Json::formatJsonPath(*portFieldOpt);

            cfg.sourcePaths.push_back(ipPath);
            cfg.sourcePaths.push_back(portPath);

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
                                      bool trace)
{
    auto opFn = [kvdbIocManager, config, trace](base::Event event) -> base::result::Result<base::Event>
    {
        const auto keyOpt = buildLookupKey(event, config);
        if (!keyOpt.has_value())
        {
            const auto traceMsg =
                trace ? fmt::format(FMT_IOC_SOURCE_MISSING_TRACE, config.iocType, config.sourceFields) : std::string {};
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }

        const auto& lookupKey = *keyOpt;
        auto iocValue = kvdbIocManager->get(config.dbName, lookupKey);
        if (!iocValue.has_value())
        {
            const auto traceMsg =
                trace ? fmt::format(FMT_IOC_NOT_FOUND_TRACE, config.iocType, lookupKey, config.sourceFields)
                      : std::string {};
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }

        // Build enrichment match
        auto enrichmentMatch = [&iocValue, &config]()
        {
            json::Json result;
            result.setObject();
            result.set("/indicator", *iocValue);
            result.setObject("/matched");
            result.setString(config.sourceFields, "/matched/field");
            return result;
        }();

        event->appendJson(enrichmentMatch, IOC_ENRICHMENT_TARGET_PATH);

        const auto traceMsg =
            trace ? fmt::format(FMT_IOC_MATCH_TRACE, config.iocType, config.sourceFields, lookupKey) : std::string {};

        return base::result::makeSuccess<decltype(event)>(event, traceMsg);
    };

    return base::Term<base::EngineOp>::create("ioc_enrichment", opFn);
}

std::pair<base::Expression, std::string>
iocEnrichmentBuilder(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbIocManager,
                     const std::vector<IocMappingConfig>& mappingConfigs,
                     std::string traceableName,
                     bool trace)
{
    if (!kvdbIocManager)
    {
        throw std::runtime_error("IOC enrichment requires a valid KVDB IOC manager");
    }

    std::vector<base::Expression> enrichmentTerms;
    enrichmentTerms.reserve(mappingConfigs.size());

    for (const auto& config : mappingConfigs)
    {
        enrichmentTerms.push_back(getEachIocEnrichTerm(kvdbIocManager, config, trace));
    }

    base::Expression enrichmentExpr = base::Chain::create(traceableName, enrichmentTerms);
    return {makeTraceableSuccessExpression(enrichmentExpr, trace), traceableName};
}

} // namespace

EnrichmentBuilder getIocEnrichmentBuilder(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbIocManager,
                                          const json::Json& configDoc,
                                          std::string_view iocType)
{
    const auto mappingConfigs = loadIocMappingConfigs(configDoc, iocType);
    const auto traceableName = fmt::format("enrichment/Ioc/{}", iocType);

    return [kvdbIocManager, mappingConfigs, traceableName](bool trace) -> std::pair<base::Expression, std::string>
    {
        return iocEnrichmentBuilder(kvdbIocManager, mappingConfigs, traceableName, trace);
    };
}

} // namespace builder::builders::enrichment

#include <fmt/format.h>

#include <store/istore.hpp>

#include "enrichment.hpp"

namespace builder::builders::enrichment
{

namespace
{

const std::string GEO_ENRICHMENT_TRACEABLE_NAMES {"enrichment/Geo"};
const base::Name DOCUMENT_GEOIP_MAPPING_COLLECTION {"enrichment/geo_mapping/0"};

// Format strings for tracing

constexpr auto FMT_NOT_FOUND_IP_ENRICHMENT_TRACE = "Geo()|AS() -> Failure: IP not found at field '{}'";

// Only Geo configuration
constexpr auto FMT_SUCCESS_GEO_ENRICHMENT_TRACE = "Geo({}) -> Success: Geo enrichment applied for IP at field '{}'";
constexpr auto FMT_NO_GEO_DATA_ENRICHMENT_TRACE = "Geo({}) -> Failure: No Geo data found for IP at field '{}'";

// Only AS configuration
constexpr auto FMT_SUCCESS_AS_ENRICHMENT_TRACE = "AS({}) -> Success: AS enrichment applied for IP at field '{}'";
constexpr auto FMT_NO_AS_DATA_ENRICHMENT_TRACE = "AS({}) -> Failure: No AS data found for IP at field '{}'";

// Both configurations
constexpr auto FMT_SUCCESS_BOTH_ENRICHMENT_TRACE =
    "Geo({})|AS({}) -> Success: Geo and AS enrichment applied for IP at field '{}'";
constexpr auto FMT_SUCCESS_ONLY_GEO_ENRICHMENT_TRACE =
    "Geo({})|AS({}) -> Success: Only Geo enrichment applied for IP at field '{}'";
constexpr auto FMT_SUCCESS_ONLY_AS_ENRICHMENT_TRACE =
    "Geo({})|AS({}) -> Success: Only AS enrichment applied for IP at field '{}'";
constexpr auto FMT_NO_DATA_ENRICHMENT_TRACE = "Geo({})|AS({}) -> Failure: No Geo or AS data found for IP at field '{}'";

/**
 * @brief Representation of the GeoIP enrichment mapping configuration for 1 field.
 */
struct MappingConfig
{
    std::string dotPath;                   ///< DotPath to the source IP address in the event (for isTestMode)
    std::string originIpPath;              ///< Path to the source IP address in the event
    std::optional<std::string> geoEcsPath; ///< Path to map GeoIP city data in ECS format
    std::optional<std::string> asEcsPath;  ///< Path to map GeoIP AS data in ECS format
};

std::vector<MappingConfig> loadMappingConfigs(const json::Json& config)
{
    if (!config.isObject())
    {
        throw std::runtime_error("GeoIP mapping configuration must be a JSON object");
    }

    const auto collection = config.getObject().value();

    std::vector<MappingConfig> mappingConfigs {};
    mappingConfigs.reserve(collection.size());

    const auto parseEcsPath = [](const json::Json& value,
                                  const std::string& jsonField,
                                  std::optional<std::string>& dest)
    {
        std::string fieldStr;
        if (value.getString(fieldStr, jsonField) == json::RetGet::Success)
        {
            dest = json::Json::formatJsonPath(fieldStr);
        }
    };

    for (const auto& [key, value] : collection)
    {
        MappingConfig cfg {};
        cfg.dotPath = key;
        cfg.originIpPath = json::Json::formatJsonPath(key);

        parseEcsPath(value, "/geo_field", cfg.geoEcsPath);
        parseEcsPath(value, "/as_field", cfg.asEcsPath);

        mappingConfigs.push_back(std::move(cfg));
    }

    return mappingConfigs;
}

/**
 * @brief Maps GeoIP data to ECS format.
 *
 * @param ip source IP address
 * @param locator Geo locator
 * @param ecsPath ECS path to map the data
 * @param event Event JSON object to populate
 * @return true if city data was mapped, false otherwise
 */
bool mapGeoToECS(const std::string& ip,
                 const std::shared_ptr<geo::ILocator>& locator,
                 const std::string& ecsPath,
                 json::Json& event)
{
    bool mapCity = false;

    // Helper lambda to map string fields
    auto mapStringField = [&](const std::string& geoPath, const std::string& ecsField)
    {
        auto result = locator->getString(ip, geoPath);
        if (!result.isError())
        {
            event.setString(result.value(), ecsPath + ecsField);
            mapCity = true;
        }
    };

    // Helper lambda to map double fields
    auto mapDoubleField = [&](const std::string& geoPath, const std::string& ecsField)
    {
        auto result = locator->getDouble(ip, geoPath);
        if (!result.isError())
        {
            event.setDouble(result.value(), ecsPath + ecsField);
            mapCity = true;
        }
    };

    // Map all geo fields using the helper lambdas
    mapStringField("city.names.en", "/city_name");
    mapStringField("continent.code", "/continent_code");
    mapStringField("continent.names.en", "/continent_name");
    mapStringField("country.iso_code", "/country_iso_code");
    mapStringField("country.names.en", "/country_name");
    mapDoubleField("location.latitude", "/location/lat");
    mapDoubleField("location.longitude", "/location/lon");
    mapStringField("postal.code", "/postal_code");
    mapStringField("location.time_zone", "/timezone");
    mapStringField("subdivisions.0.iso_code", "/region_iso_code");
    mapStringField("subdivisions.0.names.en", "/region_name");

    return mapCity;
}

/**
 * @brief Maps AS data to ECS format.
 *
 * @param ip source IP address
 * @param ecsPath ECS path to map the data
 * @param event Event JSON object to populate
 * @return true if AS data was mapped,
 * @return false otherwise
 */
bool mapAStoECS(const std::string& ip,
                const std::shared_ptr<geo::ILocator>& locator,
                const std::string& ecsPath,
                json::Json& event)
{
    bool mapAS = false;

    // Helper lambda for AS number field
    auto mapUint32Field = [&](const std::string& geoPath, const std::string& ecsField)
    {
        auto result = locator->getUint32(ip, geoPath);
        if (!result.isError())
        {
            event.setInt64(result.value(), ecsPath + ecsField);
            mapAS = true;
        }
    };

    // Helper lambda for AS string field
    auto mapStringField = [&](const std::string& geoPath, const std::string& ecsField)
    {
        auto result = locator->getString(ip, geoPath);
        if (!result.isError())
        {
            event.setString(result.value(), ecsPath + ecsField);
            mapAS = true;
        }
    };

    // Map AS fields
    mapUint32Field("autonomous_system_number", "/number");
    mapStringField("autonomous_system_organization", "/organization/name");

    return mapAS;
}

/**
 * @brief Generates an expression for geographic and AS number enrichment of events.
 *
 * Creates a term-based operation that enriches events with GeoIP and AS number data.
 * The function retrieves an IP address from the event (supporting both single values
 * and array formats), then maps the corresponding geographic and/or AS information
 * to ECS-compliant fields based on the provided configuration.
 *
 * @param cityLocator Shared pointer to the geo locator implementation for geographic lookups
 * @param asLocator Shared pointer to the AS locator implementation for AS number lookups
 * @param mappingConfig Configuration object specifying:
 *                      - originIpPath: Path to the source IP field in the event
 *                      - asEcsPath: Optional path for AS number ECS field mapping
 *                      - geoEcsPath: Optional path for geographic ECS field mapping
 *                      - dotPath: Dot notation path used for isTestMode logging
 * @param isTestMode Boolean flag to enable detailed isTestMode logging of enrichment results
 *
 * @return base::Expression A Term expression that performs the enrichment operation.
 *                          The operation:
 *                          - Extracts the source IP from the event
 *                          - Maps AS and/or geographic data based on configuration
 *                          - Returns success with optional isTestMode message if enrichment
 *                            criteria are met (at least one mapping configured)
 *                          - Returns failure if IP not found or no enrichment succeeds
 */
base::Expression getEachEnrichTerm(const std::shared_ptr<geo::ILocator>& cityLocator,
                                   const std::shared_ptr<geo::ILocator>& asLocator,
                                   const MappingConfig& mappingConfig,
                                   bool isTestMode,
                                   const std::shared_ptr<bool>& enrichmentApplied)
{

    const json::PointerPath originIpPP(mappingConfig.originIpPath);
    const json::PointerPath originIpFirstPP(mappingConfig.originIpPath + "/0");

    /**
     * @brief Lambda function to extract the source IP address from the event, supporting both single string and array
     * formats.
     */
    const auto getIpFn = [originIpPP, originIpFirstPP](const base::Event& e) -> std::optional<std::string>
    {
        std::string ipStr;
        if ((e->getString(ipStr, originIpPP) == json::RetGet::Success)
            || e->getString(ipStr, originIpFirstPP) == json::RetGet::Success)
        {
            return ipStr;
        }
        return std::nullopt;
    };

    auto opFn = [cityLocator, asLocator, mappingConfig, isTestMode, getIpFn, enrichmentApplied](
                    base::Event event) -> base::result::Result<base::Event>
    {
        // Get source IP, can be an string o a array of strings, in that case we take the first one.
        const auto ipOpt = getIpFn(event);

        if (!ipOpt.has_value())
        {
            const auto traceMsg =
                isTestMode ? fmt::format(FMT_NOT_FOUND_IP_ENRICHMENT_TRACE, mappingConfig.dotPath) : std::string {};
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }
        const auto& ip = ipOpt.value();

        // Map enrichment data
        const bool asConfigured = mappingConfig.asEcsPath.has_value();
        const bool geoConfigured = mappingConfig.geoEcsPath.has_value();

        const bool asSuccess =
            asConfigured ? mapAStoECS(ip, asLocator, mappingConfig.asEcsPath.value(), *event) : false;

        const bool geoSuccess =
            geoConfigured ? mapGeoToECS(ip, cityLocator, mappingConfig.geoEcsPath.value(), *event) : false;

        if (asSuccess || geoSuccess)
        {
            *enrichmentApplied = true;
        }

        // Generate isTestMode message using lookup lambda
        const auto getTraceMessage = [&]() -> std::string
        {
            if (!isTestMode)
                return {};

            // Lambda to generate message based on configuration type
            auto msgForBothConfigs = [&]()
            {
                if (asSuccess && geoSuccess)
                    return fmt::format(FMT_SUCCESS_BOTH_ENRICHMENT_TRACE, ip, ip, mappingConfig.dotPath);
                if (asSuccess)
                    return fmt::format(FMT_SUCCESS_ONLY_AS_ENRICHMENT_TRACE, ip, ip, mappingConfig.dotPath);
                if (geoSuccess)
                    return fmt::format(FMT_SUCCESS_ONLY_GEO_ENRICHMENT_TRACE, ip, ip, mappingConfig.dotPath);
                return fmt::format(FMT_NO_DATA_ENRICHMENT_TRACE, ip, ip, mappingConfig.dotPath);
            };

            auto msgForAsOnly = [&]()
            {
                return asSuccess ? fmt::format(FMT_SUCCESS_AS_ENRICHMENT_TRACE, ip, mappingConfig.dotPath)
                                 : fmt::format(FMT_NO_AS_DATA_ENRICHMENT_TRACE, ip, mappingConfig.dotPath);
            };

            auto msgForGeoOnly = [&]()
            {
                return geoSuccess ? fmt::format(FMT_SUCCESS_GEO_ENRICHMENT_TRACE, ip, mappingConfig.dotPath)
                                  : fmt::format(FMT_NO_GEO_DATA_ENRICHMENT_TRACE, ip, mappingConfig.dotPath);
            };

            if (asConfigured && geoConfigured)
                return msgForBothConfigs();
            if (asConfigured)
                return msgForAsOnly();
            if (geoConfigured)
                return msgForGeoOnly();
            return {};
        };

        return base::result::makeSuccess<decltype(event)>(event, getTraceMessage());
    };

    return base::Term<base::EngineOp>::create("geo_as_enrichment", opFn);
};

/**
 * @brief Builds a geo enrichment expression that combines multiple geo-location data sources.
 *
 * This function creates a composite enrichment expression by combining ASN (Autonomous System Number)
 * and CITY geo-location locators. It processes multiple mapping configurations and returns a traceable
 * expression that can be used to enrich data with geographic information.
 *
 * @param geoManager Shared pointer to the geo manager interface responsible for managing
 *                   geo-location data sources and locators.
 * @param mappingConfigs Vector of mapping configurations that define how geo-location data
 *                       should be applied and mapped to the enrichment expression.
 * @param isTestMode Boolean flag indicating whether tracing information should be included in
 *              the generated expression for logtest/tester.
 *
 * @return A pair containing:
 *         - first: A base::Expression representing the complete geo enrichment expression
 *                  with optional tracing capability.
 *         - second: A string constant (GEO_ENRICHMENT_TRACEABLE_NAMES) identifying the
 *                   enrichment expression for reference and tracing.
 *
 * @throws std::runtime_error If the ASN locator cannot be retrieved from the geo manager,
 *                            with message "Error getting geo asn locator: " + error details.
 * @throws std::runtime_error If the CITY locator cannot be retrieved from the geo manager,
 *                            with message "Error getting geo city locator: " + error details.
 *
 * @note The function combines individual enrichment terms into a single Chain expression
 *       for efficient processing of geographic data enrichment.
 */
std::pair<base::Expression, std::string> geoEnrichmentBuilder(const std::shared_ptr<geo::IManager>& geoManager,
                                                              const std::vector<MappingConfig>& mappingConfigs,
                                                              bool isTestMode)
{

    // Get locators
    auto as = geoManager->getLocator(geo::Type::ASN);
    auto city = geoManager->getLocator(geo::Type::CITY);

    if (as.isError())
    {
        throw std::runtime_error("Error getting geo asn locator: " + as.readableStr());
    }
    if (city.isError())
    {
        throw std::runtime_error("Error getting geo city locator: " + city.readableStr());
    }

    // Create locators
    auto& asLocator = as.value();
    auto& cityLocator = city.value();

    // Shared flag to track if any enrichment was applied
    auto enrichmentApplied = std::make_shared<bool>(false);

    // Create enrichment terms for each mapping config
    std::vector<base::Expression> enrichmentTerms;
    for (const auto& config : mappingConfigs)
    {
        enrichmentTerms.push_back(getEachEnrichTerm(cityLocator, asLocator, config, isTestMode, enrichmentApplied));
    }

    // Combine terms into a single expression
    base::Expression enrichmentExpr = base::Chain::create(GEO_ENRICHMENT_TRACEABLE_NAMES, enrichmentTerms);

    if (!isTestMode)
    {
        return {enrichmentExpr, GEO_ENRICHMENT_TRACEABLE_NAMES};
    }

    // Only emit SUCCESS if at least one enrichment was applied
    auto conditionalSuccess =
        base::Term<base::EngineOp>::create("ConditionalAccept",
                                           [enrichmentApplied](auto e) -> base::result::Result<base::Event>
                                           {
                                               if (*enrichmentApplied)
                                               {
                                                   *enrichmentApplied = false;
                                                   return base::result::makeSuccess(e, "SUCCESS");
                                               }
                                               return base::result::makeFailure(e, std::string {});
                                           });

    return {base::Implication::create("TraceableConditional", enrichmentExpr, conditionalSuccess),
            GEO_ENRICHMENT_TRACEABLE_NAMES};
};

} // namespace

EnrichmentBuilder getGeoEnrichmentBuilder(const std::shared_ptr<geo::IManager>& geoManager, const json::Json& configDoc)
{
    const auto mappingConfigs = loadMappingConfigs(configDoc);
    return [geoManager, mappingConfigs](bool isTestMode) -> std::pair<base::Expression, std::string>
    {
        return geoEnrichmentBuilder(geoManager, mappingConfigs, isTestMode);
    };
}

} // namespace builder::builders::enrichment

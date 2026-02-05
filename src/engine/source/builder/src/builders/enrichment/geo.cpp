#include <fmt/format.h>

#include "enrichment.hpp"

namespace builder::builders::enrichment
{

namespace
{

const std::string GEO_ENRICHMENT_TRACEABLE_NAMES {"enrichment/Geo"};

// Format strings for tracing

constexpr auto FMT_NOT_FOUND_IP_ENRICHMENT_TRACE = "Geo()|AS() -> Failure: IP not found at path '{}'";

// Only Geo configuration
constexpr auto FMT_SUCCESS_GEO_ENRICHMENT_TRACE = "Geo({}) -> Success: Geo enrichment applied for IP";
constexpr auto FMT_NO_GEO_DATA_ENRICHMENT_TRACE = "Geo({}) -> Failure: No Geo data found for IP";

// Only AS configuration
constexpr auto FMT_SUCCESS_AS_ENRICHMENT_TRACE = "AS({}) -> Success: AS enrichment applied for IP";
constexpr auto FMT_NO_AS_DATA_ENRICHMENT_TRACE = "AS({}) -> Failure: No AS data found for IP";

// Both configurations
constexpr auto FMT_SUCCESS_BOTH_ENRICHMENT_TRACE = "Geo({})|AS({}) -> Success: Geo and AS enrichment applied for IP";
constexpr auto FMT_SUCCESS_ONLY_GEO_ENRICHMENT_TRACE = "Geo({})|AS({}) -> Success: Only Geo enrichment applied for IP";
constexpr auto FMT_SUCCESS_ONLY_AS_ENRICHMENT_TRACE = "Geo({})|AS({}) -> Success: Only AS enrichment applied for IP";
constexpr auto FMT_NO_DATA_ENRICHMENT_TRACE = "Geo({})|AS({}) -> Failure: No Geo or AS data found for IP";

/**
 * @brief Representation of the GeoIP enrichment mapping configuration for 1 field.
 */
struct MappingConfig
{
    std::string originIpPath;              ///< Path to the source IP address in the event
    std::optional<std::string> geoEcsPath; ///< Path to map GeoIP city data in ECS format
    std::optional<std::string> asEcsPath;  ///< Path to map GeoIP AS data in ECS format
};

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
    // Geo data
    auto city = locator->getString(ip, "city.names.en");
    if (!base::isError(city))
    {
        event.setString(getResponse(city), ecsPath + "/city_name");
        mapCity = true;
    }

    auto continentCode = locator->getString(ip, "continent.code");
    if (!base::isError(continentCode))
    {
        event.setString(getResponse(continentCode), ecsPath + "/continent_code");
        mapCity = true;
    }

    auto continentName = locator->getString(ip, "continent.names.en");
    if (!base::isError(continentName))
    {
        event.setString(getResponse(continentName), ecsPath + "/continent_name");
        mapCity = true;
    }

    auto countryIsoCode = locator->getString(ip, "country.iso_code");
    if (!base::isError(countryIsoCode))
    {
        event.setString(getResponse(countryIsoCode), ecsPath + "/country_iso_code");
        mapCity = true;
    }

    auto countryName = locator->getString(ip, "country.names.en");
    if (!base::isError(countryName))
    {
        event.setString(getResponse(countryName), ecsPath + "/country_name");
        mapCity = true;
    }

    auto lat = locator->getDouble(ip, "location.latitude");
    if (!base::isError(lat))
    {
        event.setDouble(getResponse(lat), ecsPath + "/location/lat");
        mapCity = true;
    }

    auto lon = locator->getDouble(ip, "location.longitude");
    if (!base::isError(lon))
    {
        event.setDouble(getResponse(lon), ecsPath + "/location/lon");
        mapCity = true;
    }

    auto postalCode = locator->getString(ip, "postal.code");
    if (!base::isError(postalCode))
    {
        event.setString(getResponse(postalCode), ecsPath + "/postal_code");
        mapCity = true;
    }

    auto timeZone = locator->getString(ip, "location.time_zone");
    if (!base::isError(timeZone))
    {
        event.setString(getResponse(timeZone), ecsPath + "/timezone");
        mapCity = true;
    }

    auto regionIsoCode = locator->getString(ip, "subdivisions.0.iso_code");
    if (!base::isError(regionIsoCode))
    {
        event.setString(getResponse(regionIsoCode), ecsPath + "/region_iso_code");
        mapCity = true;
    }

    auto regionName = locator->getString(ip, "subdivisions.0.names.en");
    if (!base::isError(regionName))
    {
        event.setString(getResponse(regionName), ecsPath + "/region_name");
        mapCity = true;
    }

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

    auto asn = locator->getUint32(ip, "autonomous_system_number");
    if (!base::isError(asn))
    {
        event.setInt64(getResponse(asn), ecsPath + "/number");
        mapAS = true;
    }

    auto asnOrg = locator->getString(ip, "autonomous_system_organization");
    if (!base::isError(asnOrg))
    {
        event.setString(getResponse(asnOrg), ecsPath + "/organization/name");
        mapAS = true;
    }

    return mapAS;
}

base::Expression
getEachEnrichTerm(const std::shared_ptr<geo::ILocator>& locator, const MappingConfig& mappingConfig, bool trace)
{

    auto opFn = [locator, mappingConfig, trace](base::Event event) -> base::result::Result<base::Event>
    {
        std::string traceMsg {};
        // Get source IP
        auto ipOpt = event->getString(mappingConfig.originIpPath);
        if (!ipOpt.has_value())
        {
            if (trace)
            {
                traceMsg = fmt::format(FMT_NOT_FOUND_IP_ENRICHMENT_TRACE, mappingConfig.originIpPath);
            }
            return base::result::makeFailure<decltype(event)>(event, traceMsg);
        }
        const auto& ip = ipOpt.value();

        // Map AS data
        bool asSuccess = false;
        if (mappingConfig.asEcsPath.has_value())
        {
            asSuccess = mapAStoECS(ip, locator, mappingConfig.asEcsPath.value(), *event);
        }

        // Map Geo data
        bool geoSuccess = false;
        if (mappingConfig.geoEcsPath.has_value())
        {
            geoSuccess = mapGeoToECS(ip, locator, mappingConfig.geoEcsPath.value(), *event);
        }

        if (trace)
        {
            if (mappingConfig.asEcsPath.has_value() && mappingConfig.geoEcsPath.has_value())
            {
                if (asSuccess && geoSuccess)
                {
                    traceMsg = fmt::format(FMT_SUCCESS_BOTH_ENRICHMENT_TRACE, ip, ip);
                }
                else if (asSuccess)
                {
                    traceMsg = fmt::format(FMT_SUCCESS_ONLY_AS_ENRICHMENT_TRACE, ip, ip);
                }
                else if (geoSuccess)
                {
                    traceMsg = fmt::format(FMT_SUCCESS_ONLY_GEO_ENRICHMENT_TRACE, ip, ip);
                }
                else
                {
                    traceMsg = fmt::format(FMT_NO_DATA_ENRICHMENT_TRACE, ip, ip);
                }
            }
            else if (mappingConfig.asEcsPath.has_value())
            {
                traceMsg = asSuccess ? fmt::format(FMT_SUCCESS_AS_ENRICHMENT_TRACE, ip)
                                     : fmt::format(FMT_NO_AS_DATA_ENRICHMENT_TRACE, ip);
            }
            else if (mappingConfig.geoEcsPath.has_value())
            {
                traceMsg = geoSuccess
                               ? fmt::format(FMT_SUCCESS_GEO_ENRICHMENT_TRACE, ip)
                               : fmt::format(FMT_NO_GEO_DATA_ENRICHMENT_TRACE, ip);
            }
        }

        return base::result::makeSuccess<decltype(event)>(event, traceMsg);
    };

    return base::Term<base::EngineOp>::create("geo_as_enrichment", opFn);
};

std::pair<base::Expression, std::string> geoEnrichmentBuilder(const std::shared_ptr<geo::IManager>& geoManager,
                                                              bool trace)
{

    // Get locators
    auto as = geoManager->getLocator(geo::Type::ASN);
    auto city = geoManager->getLocator(geo::Type::CITY);

    // Testing configuration
    std::vector<MappingConfig> mappingConfigs = {
        {
            .originIpPath = "/tmp_json/src/ip",
            .geoEcsPath = "/tmp/src/geo",
            .asEcsPath = "/tmp/src/as",
        },
        {
            .originIpPath = "/tmp_json/dst/ip",
            .geoEcsPath = "/tmp/dst/geo",
            .asEcsPath = "/tmp/dst/as",
        },
    };

    if (base::isError(as))
    {
        throw std::runtime_error("Error getting geo asn locator: " + base::getError(as).message);
    }
    if (base::isError(city))
    {
        throw std::runtime_error("Error getting geo city locator: " + base::getError(city).message);
    }

    // Create locators
    auto& asLocator = base::getResponse(as);
    auto& cityLocator = base::getResponse(city);

    // Create enrichment terms for each mapping config
    std::vector<base::Expression> enrichmentTerms;
    for (const auto& config : mappingConfigs)
    {
        enrichmentTerms.push_back(getEachEnrichTerm(cityLocator, config, trace));
    }

    // Combine terms into a single expression
    base::Expression enrichmentExpr = base::Chain::create(GEO_ENRICHMENT_TRACEABLE_NAMES, enrichmentTerms);

    return {makeTraceableSuccessExpression(enrichmentExpr, trace), GEO_ENRICHMENT_TRACEABLE_NAMES};
};

} // namespace

EnrichmentBuilder getGeoEnrichmentBuilder(const std::shared_ptr<geo::IManager>& geoManager)
{
    return [geoManager](bool trace) -> std::pair<base::Expression, std::string>
    {
        return geoEnrichmentBuilder(geoManager, trace);
    };
}

} // namespace builder::builders::enrichment

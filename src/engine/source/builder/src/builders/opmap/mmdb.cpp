#include "mmdb.hpp"

namespace builder::builders::mmdb
{

namespace
{

// Only for the MMDB City / Country db
json::Json mapGeoToECS(const std::string& ip, const std::shared_ptr<geo::ILocator>& locator)
{
    json::Json cityData;
    cityData.setObject();

    // Geo data
    auto city = locator->getString(ip, "city.names.en");
    if (!city.isError())
    {
        cityData.setString(city.value(), "/city_name");
    }

    auto continentCode = locator->getString(ip, "continent.code");
    if (!continentCode.isError())
    {
        cityData.setString(continentCode.value(), "/continent_code");
    }

    auto continentName = locator->getString(ip, "continent.names.en");
    if (!continentName.isError())
    {
        cityData.setString(continentName.value(), "/continent_name");
    }

    auto countryIsoCode = locator->getString(ip, "country.iso_code");
    if (!countryIsoCode.isError())
    {
        cityData.setString(countryIsoCode.value(), "/country_iso_code");
    }

    auto countryName = locator->getString(ip, "country.names.en");
    if (!countryName.isError())
    {
        cityData.setString(countryName.value(), "/country_name");
    }

    auto lat = locator->getDouble(ip, "location.latitude");
    if (!lat.isError())
    {
        cityData.setDouble(lat.value(), "/location/lat");
    }

    auto lon = locator->getDouble(ip, "location.longitude");
    if (!lon.isError())
    {
        cityData.setDouble(lon.value(), "/location/lon");
    }

    auto postalCode = locator->getString(ip, "postal.code");
    if (!postalCode.isError())
    {
        cityData.setString(postalCode.value(), "/postal_code");
    }

    auto timeZone = locator->getString(ip, "location.time_zone");
    if (!timeZone.isError())
    {
        cityData.setString(timeZone.value(), "/timezone");
    }

    auto regionIsoCode = locator->getString(ip, "subdivisions.0.iso_code");
    if (!regionIsoCode.isError())
    {
        cityData.setString(regionIsoCode.value(), "/region_iso_code");
    }

    auto regionName = locator->getString(ip, "subdivisions.0.names.en");
    if (!regionName.isError())
    {
        cityData.setString(regionName.value(), "/region_name");
    }

    return cityData;
}

json::Json mapAStoECS(const std::string& ip, const std::shared_ptr<geo::ILocator>& locator)
{
    json::Json asData;
    asData.setObject();

    auto asn = locator->getUint32(ip, "autonomous_system_number");
    if (!asn.isError())
    {
        asData.setInt64(asn.value(), "/number");
    }

    auto asnOrg = locator->getString(ip, "autonomous_system_organization");
    if (!asnOrg.isError())
    {
        asData.setString(asnOrg.value(), "/organization/name");
    }

    return asData;
}

} // namespace

MapBuilder getMMDBGeoBuilder(const std::shared_ptr<geo::IManager>& geoManager)
{
    return [geoManager](const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
        utils::assertRef(opArgs, 0);

        const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& validator = buildCtx->validator();

        // Geo only accepts IP
        if (validator.hasField(ipRef.dotPath()) && validator.getType(ipRef.dotPath()) != schemf::Type::IP)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an IP.", ipRef.dotPath()));
        }

        const auto name = buildCtx->context().opName;

        const std::string successTrace {fmt::format("{} -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("{} -> Failure: Reference to ip {} not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("{} -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("{} -> Failure: IP Not found in DB", name)};
        const std::string emptyDataTrace {fmt::format("{} -> Failure: Empty wcs data", name)};

        auto resDB = geoManager->getLocator(geo::Type::CITY);
        auto runstate = buildCtx->runState();

        return [=, locator = resDB.value(), srcRef = ipRef.jsonPath()](base::ConstEvent event) -> MapResult
        {
            // Get the ip
            std::string ipStr;
            if (event->getString(ipStr, srcRef) != json::RetGet::Success)
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundTrace);
            }

            auto geo = mapGeoToECS(ipStr, locator);

            if (geo.size() == 0)
            {
                RETURN_FAILURE(runstate, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(runstate, geo, successTrace);
        };
    };
};

MapBuilder getMMDBASNBuilder(const std::shared_ptr<geo::IManager>& geoManager)
{
    return [geoManager](const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        const auto name = buildCtx->context().opName;

        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
        utils::assertRef(opArgs, 0);

        const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& validator = buildCtx->validator();

        const std::string successTrace {fmt::format("{} -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("{} -> Failure: Reference to ip {} not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("{} -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("{} -> Failure: IP Not found in DB", name)};
        const std::string emptyDataTrace {fmt::format("{} -> Failure: Empty wcs data", name)};

        // Geo only accepts IP
        if (validator.hasField(ipRef.dotPath()) && validator.getType(ipRef.dotPath()) != schemf::Type::IP)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an IP.", ipRef.dotPath()));
        }

        auto resDB = geoManager->getLocator(geo::Type::ASN);
        auto runstate = buildCtx->runState();

        return [=, locator = resDB.value(), srcRef = ipRef.jsonPath()](base::ConstEvent event) -> MapResult
        {
            // Get the ip
            std::string ipStr;
            if (event->getString(ipStr, srcRef) != json::RetGet::Success)
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundTrace);
            }

            auto as = mapAStoECS(ipStr, locator);

            if (as.size() == 0)
            {
                RETURN_FAILURE(runstate, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(runstate, as, successTrace);
        };
    };
};

} // namespace builder::builders::mmdb

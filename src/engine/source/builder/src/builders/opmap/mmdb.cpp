#include "mmdb.hpp"

namespace builder::builders::mmdb
{

namespace
{
MapOp dumpFailTransform(const std::string& trace, const std::shared_ptr<const RunState>& runstate)
{

    return [trace, runstate](base::ConstEvent event) -> MapResult
    {
        RETURN_FAILURE(runstate, json::Json {}, trace);
    };
}

// Only for the MMDB City / Country db
json::Json mapGeoToECS(const std::string& ip, const std::shared_ptr<geo::ILocator>& locator)
{
    json::Json cityData;
    cityData.setObject();

    // Geo data
    auto city = locator->getString(ip, "city.names.en");
    if (!base::isError(city))
    {
        cityData.setString(getResponse(city), "/city_name");
    }

    auto continentCode = locator->getString(ip, "continent.code");
    if (!base::isError(continentCode))
    {
        cityData.setString(getResponse(continentCode), "/continent_code");
    }

    auto continentName = locator->getString(ip, "continent.names.en");
    if (!base::isError(continentName))
    {
        cityData.setString(getResponse(continentName), "/continent_name");
    }

    auto countryIsoCode = locator->getString(ip, "country.iso_code");
    if (!base::isError(countryIsoCode))
    {
        cityData.setString(getResponse(countryIsoCode), "/country_iso_code");
    }

    auto countryName = locator->getString(ip, "country.names.en");
    if (!base::isError(countryName))
    {
        cityData.setString(getResponse(countryName), "/country_name");
    }

    auto lat = locator->getDouble(ip, "location.latitude");
    if (!base::isError(lat))
    {
        cityData.setDouble(getResponse(lat), "/location/lat");
    }

    auto lon = locator->getDouble(ip, "location.longitude");
    if (!base::isError(lon))
    {
        cityData.setDouble(getResponse(lon), "/location/lon");
    }

    auto postalCode = locator->getString(ip, "postal.code");
    if (!base::isError(postalCode))
    {
        cityData.setString(getResponse(postalCode), "/postal_code");
    }

    auto timeZone = locator->getString(ip, "location.time_zone");
    if (!base::isError(timeZone))
    {
        cityData.setString(getResponse(timeZone), "/timezone");
    }

    auto regionIsoCode = locator->getString(ip, "subdivisions.0.iso_code");
    if (!base::isError(regionIsoCode))
    {
        cityData.setString(getResponse(regionIsoCode), "/region_iso_code");
    }

    auto regionName = locator->getString(ip, "subdivisions.0.names.en");
    if (!base::isError(regionName))
    {
        cityData.setString(getResponse(regionName), "/region_name");
    }

    return cityData;
}

json::Json mapAStoECS(const std::string& ip, const std::shared_ptr<geo::ILocator>& locator)
{
    json::Json asData;
    asData.setObject();

    auto asn = locator->getUint32(ip, "autonomous_system_number");
    if (!base::isError(asn))
    {
        asData.setInt64(getResponse(asn), "/number");
    }

    auto asnOrg = locator->getString(ip, "autonomous_system_organization");
    if (!base::isError(asnOrg))
    {
        asData.setString(getResponse(asnOrg), "/organization/name");
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

        auto resDB = geoManager->getLocator(geo::Type::CITY);
        // TODO Temporary error handling, this should be mandatory
        auto runstate = buildCtx->runState();
        const auto name = buildCtx->context().opName;
        if (base::isError(resDB))
        {
            const auto trace = fmt::format("{} -> Failure: handler error: {}", name, base::getError(resDB).message);
            return dumpFailTransform(trace, runstate);
        }

        const std::string successTrace {fmt::format("{} -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("{} -> Failure: Reference to ip {} not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("{} -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("{} -> Failure: IP Not found in DB", name)};
        const std::string emptyDataTrace {fmt::format("{} -> Failure: Empty wcs data", name)};

        return [=, locator = base::getResponse(resDB), srcRef = ipRef.jsonPath()](base::ConstEvent event) -> MapResult
        {
            // Get the ip
            auto ipStr = event->getString(srcRef);
            if (!ipStr)
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundTrace);
            }

            auto geo = mapGeoToECS(ipStr.value(), locator);

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
        // TODO Temporary error handling, this should be mandatory
        auto runstate = buildCtx->runState();
        if (base::isError(resDB))
        {
            return dumpFailTransform("Error getting geo asn locator: " + base::getError(resDB).message, runstate);
        }

        return [=, locator = base::getResponse(resDB), srcRef = ipRef.jsonPath()](base::ConstEvent event) -> MapResult
        {
            // Get the ip
            auto ipStr = event->getString(srcRef);
            if (!ipStr)
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundTrace);
            }

            auto as = mapAStoECS(ipStr.value(), locator);

            if (as.size() == 0)
            {
                RETURN_FAILURE(runstate, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(runstate, as, successTrace);
        };
    };
};

} // namespace builder::builders::mmdb

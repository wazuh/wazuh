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
json::Json mapGeoToECS(const std::shared_ptr<::mmdb::IResult>& result)
{
    json::Json cityData;
    cityData.setObject();

    // Geo data
    auto city = result->getString("city.names.en");
    if (!base::isError(city))
    {
        cityData.setString(getResponse(city), "/city_name");
    }

    auto continentCode = result->getString("continent.code");
    if (!base::isError(continentCode))
    {
        cityData.setString(getResponse(continentCode), "/continent_code");
    }

    auto continentName = result->getString("continent.names.en");
    if (!base::isError(continentName))
    {
        cityData.setString(getResponse(continentName), "/continent_name");
    }

    auto countryIsoCode = result->getString("country.iso_code");
    if (!base::isError(countryIsoCode))
    {
        cityData.setString(getResponse(countryIsoCode), "/country_iso_code");
    }

    auto countryName = result->getString("country.names.en");
    if (!base::isError(countryName))
    {
        cityData.setString(getResponse(countryName), "/country_name");
    }

    auto lat = result->getDouble("location.latitude");
    if (!base::isError(lat))
    {
        cityData.setDouble(getResponse(lat), "/location/lat");
    }

    auto lon = result->getDouble("location.longitude");
    if (!base::isError(lon))
    {
        cityData.setDouble(getResponse(lon), "/location/lon");
    }

    auto postalCode = result->getString("postal.code");
    if (!base::isError(postalCode))
    {
        cityData.setString(getResponse(postalCode), "/postal_code");
    }

    auto timeZone = result->getString("location.time_zone");
    if (!base::isError(timeZone))
    {
        cityData.setString(getResponse(timeZone), "/timezone");
    }

    auto regionIsoCode = result->getString("subdivisions.0.iso_code");
    if (!base::isError(regionIsoCode))
    {
        cityData.setString(getResponse(regionIsoCode), "/region_iso_code");
    }

    auto regionName = result->getString("subdivisions.0.names.en");
    if (!base::isError(regionName))
    {
        cityData.setString(getResponse(regionName), "/region_name");
    }

    return cityData;
}

json::Json mapAStoECS(const std::shared_ptr<::mmdb::IResult>& result)
{
    json::Json asData;
    asData.setObject();

    auto asn = result->getUint32("autonomous_system_number");
    if (!base::isError(asn))
    {
        asData.setInt64(getResponse(asn), "/number");
    }

    auto asnOrg = result->getString("autonomous_system_organization");
    if (!base::isError(asnOrg))
    {
        asData.setString(getResponse(asnOrg), "/organization/name");
    }

    return asData;
}

} // namespace

MapBuilder getMMDBGeoBuilder(const std::shared_ptr<::mmdb::IManager>& mmdbManager)
{
    return [mmdbManager](const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {

        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
        utils::assertRef(opArgs, 0);

        const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& schema = buildCtx->schema();

        // Geo only accepts IP
        if (schema.hasField(ipRef.dotPath()) && schema.getType(ipRef.dotPath()) != schemf::Type::IP)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an IP.", ipRef.dotPath()));
        }

        auto resDB = mmdbManager->getHandler("mm-geolite2-city");
        // TODO Temporary error handling, this should be mandatory
        auto runstate = buildCtx->runState();
        const auto name = buildCtx->context().opName;
        if (base::isError(resDB))
        {
            const auto trace =  fmt::format("{} -> Failure: handler error: {}", name, base::getError(resDB).message);
            return dumpFailTransform(trace, runstate);
        }

        const std::string successTrace {fmt::format("{} -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("{} -> Failure: Reference to ip {} not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("{} -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("{} -> Failure: IP Not found in DB", name)};
        const std::string emptyDataTrace {fmt::format("{} -> Failure: Empty wcs data", name)};

        // auto dbHandler = base::getResponse<std::shared_ptr<::mmdb::IHandler>>(resDB);
        return [=, dbHandler = base::getResponse(resDB), srcRef = ipRef.jsonPath()](
                   base::ConstEvent event) -> MapResult
        {
            // Get the ip
            auto ipStr = event->getString(srcRef);
            if (!ipStr)
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundTrace);
            }

            // Check if the ip is valid
            std::shared_ptr<::mmdb::IResult> result;
            try
            {
                result = dbHandler->lookup(ipStr.value());
            }
            catch (std::runtime_error& e)
            {
                RETURN_FAILURE(runstate, json::Json {}, notValidIPTrace + " " + e.what());
            }

            if (!result->hasData())
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundDBTrace);
            }

            auto geo = mapGeoToECS(result);

            if (geo.size() == 0)
            {
                RETURN_FAILURE(runstate, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(runstate, geo, successTrace);
        };
    };
};

MapBuilder getMMDBASNBuilder(const std::shared_ptr<::mmdb::IManager>& mmdbManager)
{
    return [mmdbManager](const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        const auto name = buildCtx->context().opName;

        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
        utils::assertRef(opArgs, 0);

        const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& schema = buildCtx->schema();

        const std::string successTrace {fmt::format("{} -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("{} -> Failure: Reference to ip {} not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("{} -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("{} -> Failure: IP Not found in DB", name)};
        const std::string emptyDataTrace {fmt::format("{} -> Failure: Empty wcs data", name)};

        // Geo only accepts IP
        if (schema.hasField(ipRef.dotPath()) && schema.getType(ipRef.dotPath()) != schemf::Type::IP)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an IP.", ipRef.dotPath()));
        }

        auto resDB = mmdbManager->getHandler("mm-geolite2-asn");
        // TODO Temporary error handling, this should be mandatory
        auto runstate = buildCtx->runState();
        if (base::isError(resDB))
        {
            return dumpFailTransform("Error getting mmdb handler: " + base::getError(resDB).message, runstate);
        }

        // auto dbHandler = base::getResponse<std::shared_ptr<::mmdb::IHandler>>(resDB);
        return [=, dbHandler = base::getResponse(resDB), srcRef = ipRef.jsonPath()](
                   base::ConstEvent event) -> MapResult
        {
            // Get the ip
            auto ipStr = event->getString(srcRef);
            if (!ipStr)
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundTrace);
            }

            // Check if the ip is valid
            std::shared_ptr<::mmdb::IResult> result;
            try
            {
                result = dbHandler->lookup(ipStr.value());
            }
            catch (std::runtime_error& e)
            {
                RETURN_FAILURE(runstate, json::Json {}, notValidIPTrace + " " + e.what());
            }

            if (!result->hasData())
            {
                RETURN_FAILURE(runstate, json::Json {}, notFoundDBTrace);
            }

            auto as = mapAStoECS(result);

            if (as.size() == 0)
            {
                RETURN_FAILURE(runstate, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(runstate, as, successTrace);
        };
    };
};

} // namespace builder::builders::mmdb

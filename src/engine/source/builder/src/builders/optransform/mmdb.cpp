#include "mmdb.hpp"

namespace builder::builders::mmdb
{

namespace
{
TransformOp dumpFailTransform(const std::string& trace, const std::shared_ptr<const RunState>& runstate)
{

    return [trace, runstate](base::Event event) -> TransformResult
    {
        RETURN_FAILURE(runstate, event, trace);
    };
}

// Only for the MMDB City / Country db
json::Json getGeoCityECS(const std::shared_ptr<::mmdb::IResult>& result)
{
    json::Json cityData;
    cityData.setObject();

    // Geo data
    auto city = result->getString("city.names.en");
    if (!base::isError(city))
    {
        cityData.setString(getResponse(city), "/geo/city_name");
    }

    auto continentCode = result->getString("continent.code");
    if (!base::isError(continentCode))
    {
        cityData.setString(getResponse(continentCode), "/geo/continent_code");
    }

    auto continentName = result->getString("continent.names.en");
    if (!base::isError(continentName))
    {
        cityData.setString(getResponse(continentName), "/geo/continent_name");
    }

    auto countryIsoCode = result->getString("country.iso_code");
    if (!base::isError(countryIsoCode))
    {
        cityData.setString(getResponse(countryIsoCode), "/geo/country_iso_code");
    }

    auto countryName = result->getString("country.names.en");
    if (!base::isError(countryName))
    {
        cityData.setString(getResponse(countryName), "/geo/country_name");
    }

    auto lat = result->getDouble("location.latitude");
    if (!base::isError(lat))
    {
        cityData.setDouble(getResponse(lat), "/geo/location/lat");
    }

    auto lon = result->getDouble("location.longitude");
    if (!base::isError(lon))
    {
        cityData.setDouble(getResponse(lon), "/geo/location/lon");
    }

    auto postalCode = result->getString("postal.code");
    if (!base::isError(postalCode))
    {
        cityData.setString(getResponse(postalCode), "/geo/postal_code");
    }

    auto timeZone = result->getString("location.time_zone");
    if (!base::isError(timeZone))
    {
        cityData.setString(getResponse(timeZone), "/geo/timezone");
    }

    return cityData;
}

json::Json getASECS(const std::shared_ptr<::mmdb::IResult>& result)
{
    json::Json asData;
    asData.setObject();

    auto asn = result->getUint32("autonomous_system_number");
    if (!base::isError(asn))
    {
        asData.setInt64(getResponse(asn), "/as/number");
    }

    auto asnOrg = result->getString("autonomous_system_organization");
    if (!base::isError(asnOrg))
    {
        asData.setString(getResponse(asnOrg), "/as/organization/name");
    }

    return asData;
}

} // namespace

TransformBuilder getMMDBGeoBuilder(const std::shared_ptr<::mmdb::IManager>& mmdbManager)
{
    return [mmdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        const auto name = buildCtx->context().opName;

        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
        utils::assertRef(opArgs, 0);

        const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& schema = buildCtx->schema();

        const std::string successTrace {fmt::format("[{}] -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("[{}] -> Failure: Reference to ip [{}] not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("[{}] -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("[{}] -> Failure: IP Not found in DB", name)};

        // Geo only accepts IP
        if (schema.hasField(ipRef.dotPath()) && schema.getType(ipRef.dotPath()) != schemf::Type::IP)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an IP.", ipRef.dotPath()));
        }

        auto resDB = mmdbManager->getHandler("mm-geolite2-city");
        // TODO Temporary error handling, this should be mandatory
        if (base::isError(resDB))
        {
            const auto& runState = buildCtx->runState();
            return dumpFailTransform(
                fmt::format("[{}] -> Failure: handler error: {}", name, base::getError(resDB).message), runState);
        }

        // auto dbHandler = base::getResponse<std::shared_ptr<::mmdb::IHandler>>(resDB);
        return [=,
                targetField = targetField.jsonPath(),
                dbHandler = base::getResponse(resDB),
                srcRef = ipRef.jsonPath(),
                runState = buildCtx->runState()](base::Event event) -> TransformResult
        {
            // Get the ip
            auto ipStr = event->getString(srcRef);
            if (!ipStr)
            {
                RETURN_FAILURE(runState, event, notFoundTrace);
            }

            // Check if the ip is valid
            std::shared_ptr<::mmdb::IResult> result;
            try
            {
                result = dbHandler->lookup(ipStr.value());
            }
            catch (std::runtime_error& e)
            {
                RETURN_FAILURE(runState, event, notValidIPTrace + " " + e.what());
            }

            if (!result->hasData())
            {
                RETURN_FAILURE(runState, event, notFoundDBTrace);
            }

            auto geo = getGeoCityECS(result);

            if (event->exists(targetField))
            {
                event->merge(false, geo, targetField);
            }
            else
            {
                event->set(targetField, geo);
            }

            RETURN_SUCCESS(runState, event, successTrace);
        };
    };
};

TransformBuilder getMMDBASNBuilder(const std::shared_ptr<::mmdb::IManager>& mmdbManager)
{
    return [mmdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        const auto name = buildCtx->context().opName;

        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
        utils::assertRef(opArgs, 0);

        const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& schema = buildCtx->schema();

        const std::string successTrace {fmt::format("[{}] -> Success", name)};
        const std::string notFoundTrace {
            fmt::format("[{}] -> Failure: Reference to ip [{}] not found or not an string", name, ipRef.dotPath())};
        const std::string notValidIPTrace {fmt::format("[{}] -> Failure: IP string is not a valid IP.", name)};
        const std::string notFoundDBTrace {fmt::format("[{}] -> Failure: IP Not found in DB", name)};

        // Geo only accepts IP
        if (schema.hasField(ipRef.dotPath()) && schema.getType(ipRef.dotPath()) != schemf::Type::IP)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an IP.", ipRef.dotPath()));
        }

        auto resDB = mmdbManager->getHandler("mm-geolite2-asn");
        // TODO Temporary error handling, this should be mandatory
        if (base::isError(resDB))
        {
            const auto& runState = buildCtx->runState();
            return dumpFailTransform("Error getting mmdb handler: " + base::getError(resDB).message, runState);
        }

        // auto dbHandler = base::getResponse<std::shared_ptr<::mmdb::IHandler>>(resDB);
        return [=,
                targetField = targetField.jsonPath(),
                dbHandler = base::getResponse(resDB),
                srcRef = ipRef.jsonPath(),
                runState = buildCtx->runState()](base::Event event) -> TransformResult
        {
            // Get the ip
            auto ipStr = event->getString(srcRef);
            if (!ipStr)
            {
                RETURN_FAILURE(runState, event, notFoundTrace);
            }

            // Check if the ip is valid
            std::shared_ptr<::mmdb::IResult> result;
            try
            {
                result = dbHandler->lookup(ipStr.value());
            }
            catch (std::runtime_error& e)
            {
                RETURN_FAILURE(runState, event, notValidIPTrace + " " + e.what());
            }

            if (!result->hasData())
            {
                RETURN_FAILURE(runState, event, notFoundDBTrace);
            }

            auto as = getASECS(result);

            if(event->exists(targetField))
            {
                event->merge(false, as, targetField);
            }
            else
            {
                event->set(targetField, as);
            }

            RETURN_SUCCESS(runState, event, successTrace);
        };
    };
};

} // namespace builder::builders::mmdb

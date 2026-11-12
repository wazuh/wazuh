// SPDX-License-Identifier: AGPL-3.0-or-later
#include "mmdb.hpp"

namespace builder::builders::mmdb
{

namespace
{

// Parsed once per process: written on every lookup
const json::PointerPath PP_CITY_NAME {"/city_name"};
const json::PointerPath PP_CONTINENT_CODE {"/continent_code"};
const json::PointerPath PP_CONTINENT_NAME {"/continent_name"};
const json::PointerPath PP_COUNTRY_ISO_CODE {"/country_iso_code"};
const json::PointerPath PP_COUNTRY_NAME {"/country_name"};
const json::PointerPath PP_LOCATION_LAT {"/location/lat"};
const json::PointerPath PP_LOCATION_LON {"/location/lon"};
const json::PointerPath PP_POSTAL_CODE {"/postal_code"};
const json::PointerPath PP_TIMEZONE {"/timezone"};
const json::PointerPath PP_REGION_ISO_CODE {"/region_iso_code"};
const json::PointerPath PP_REGION_NAME {"/region_name"};
const json::PointerPath PP_NUMBER {"/number"};
const json::PointerPath PP_ORGANIZATION_NAME {"/organization/name"};

// Only for the MMDB City / Country db
json::Json mapGeoToECS(const std::string& ip, const std::shared_ptr<geo::ILocator>& locator)
{
    json::Json cityData;
    cityData.setObject();

    // Geo data
    auto city = locator->getString(ip, "city.names.en");
    if (!city.isError())
    {
        cityData.setString(city.value(), PP_CITY_NAME);
    }

    auto continentCode = locator->getString(ip, "continent.code");
    if (!continentCode.isError())
    {
        cityData.setString(continentCode.value(), PP_CONTINENT_CODE);
    }

    auto continentName = locator->getString(ip, "continent.names.en");
    if (!continentName.isError())
    {
        cityData.setString(continentName.value(), PP_CONTINENT_NAME);
    }

    auto countryIsoCode = locator->getString(ip, "country.iso_code");
    if (!countryIsoCode.isError())
    {
        cityData.setString(countryIsoCode.value(), PP_COUNTRY_ISO_CODE);
    }

    auto countryName = locator->getString(ip, "country.names.en");
    if (!countryName.isError())
    {
        cityData.setString(countryName.value(), PP_COUNTRY_NAME);
    }

    auto lat = locator->getDouble(ip, "location.latitude");
    if (!lat.isError())
    {
        cityData.setDouble(lat.value(), PP_LOCATION_LAT);
    }

    auto lon = locator->getDouble(ip, "location.longitude");
    if (!lon.isError())
    {
        cityData.setDouble(lon.value(), PP_LOCATION_LON);
    }

    auto postalCode = locator->getString(ip, "postal.code");
    if (!postalCode.isError())
    {
        cityData.setString(postalCode.value(), PP_POSTAL_CODE);
    }

    auto timeZone = locator->getString(ip, "location.time_zone");
    if (!timeZone.isError())
    {
        cityData.setString(timeZone.value(), PP_TIMEZONE);
    }

    auto regionIsoCode = locator->getString(ip, "subdivisions.0.iso_code");
    if (!regionIsoCode.isError())
    {
        cityData.setString(regionIsoCode.value(), PP_REGION_ISO_CODE);
    }

    auto regionName = locator->getString(ip, "subdivisions.0.names.en");
    if (!regionName.isError())
    {
        cityData.setString(regionName.value(), PP_REGION_NAME);
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
        asData.setInt64(asn.value(), PP_NUMBER);
    }

    auto asnOrg = locator->getString(ip, "autonomous_system_organization");
    if (!asnOrg.isError())
    {
        asData.setString(asnOrg.value(), PP_ORGANIZATION_NAME);
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
        if (resDB.isError())
        {
            throw std::runtime_error(
                fmt::format("{} -> Failure: Error getting geo city locator: {}", name, resDB.readableStr()));
        }

        const auto isTestMode = buildCtx->isTestMode();

        return [=, locator = resDB.value(), srcRef = json::PointerPath(ipRef.jsonPath())](
                   base::ConstEvent event) -> MapResult
        {
            // Get the ip
            std::string ipStr;
            if (event->getString(ipStr, srcRef) != json::RetGet::Success)
            {
                RETURN_FAILURE(isTestMode, json::Json {}, notFoundTrace);
            }

            auto geo = mapGeoToECS(ipStr, locator);

            if (geo.size() == 0)
            {
                RETURN_FAILURE(isTestMode, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(isTestMode, geo, successTrace);
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
        if (resDB.isError())
        {
            throw std::runtime_error(
                fmt::format("{} -> Failure: Error getting geo asn locator: {}", name, resDB.readableStr()));
        }
        const auto isTestMode = buildCtx->isTestMode();

        return [=, locator = resDB.value(), srcRef = json::PointerPath(ipRef.jsonPath())](
                   base::ConstEvent event) -> MapResult
        {
            // Get the ip
            std::string ipStr;
            if (event->getString(ipStr, srcRef) != json::RetGet::Success)
            {
                RETURN_FAILURE(isTestMode, json::Json {}, notFoundTrace);
            }

            auto as = mapAStoECS(ipStr, locator);

            if (as.size() == 0)
            {
                RETURN_FAILURE(isTestMode, json::Json {}, emptyDataTrace);
            }

            RETURN_SUCCESS(isTestMode, as, successTrace);
        };
    };
};

} // namespace builder::builders::mmdb

#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/mmdb.hpp"

#include <geo/mockLocator.hpp>
#include <geo/mockManager.hpp>

namespace
{
using namespace builder::builders::mmdb;

// Common expectations for builders and operations
auto expectContext()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, context());
        return None {};
    };
}

auto customRefExpected()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectTypeRef(schemf::Type type, bool expContxt = false)
{
    return [=](const BuildersMocks& mocks)
    {
        if (!expContxt)
        {
            EXPECT_CALL(*mocks.ctx, context());
        }
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getType(DotPath("ref"))).WillRepeatedly(testing::Return(type));
        return None {};
    };
}

auto customRefExpected(const json::Json& value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));

        return value;
    };
}

// AS: Builder getters for building test
namespace as
{
mapbuildtest::BuilderGetter getBuilderNoLocator()
{
    return []()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        return getMMDBASNBuilder(geoManager);
    };
}

mapbuildtest::BuilderGetter getBuilderWLocator(bool failLocator = false)
{
    return [=]()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        auto geoLocator = std::make_shared<::geo::mocks::MockLocator>();
        if (failLocator)
        {
            EXPECT_CALL(*geoManager, getLocator(geo::Type::ASN)).WillOnce(testing::Return(base::Error {"error"}));
        }
        else
        {
            EXPECT_CALL(*geoManager, getLocator(geo::Type::ASN)).WillOnce(testing::Return(geoLocator));
        }
        return getMMDBASNBuilder(geoManager);
    };
}

// AS operation
mapbuildtest::BuilderGetter getBuilderLocatorNoResult()
{
    return [=]()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        auto geoLocator = std::make_shared<::geo::mocks::MockLocator>();
        EXPECT_CALL(*geoManager, getLocator(geo::Type::ASN)).WillOnce(testing::Return(geoLocator));
        ON_CALL(*geoLocator, getString(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        ON_CALL(*geoLocator, getUint32(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        ON_CALL(*geoLocator, getDouble(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        ON_CALL(*geoLocator, getAsJson(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        return getMMDBASNBuilder(geoManager);
    };
}

mapbuildtest::BuilderGetter getBuilderLocatorResult(bool hasASN, bool hasASOrg)
{
    // Path from the root MaxMind object
    const DotPath asnPath {"autonomous_system_number"};
    const DotPath asOrgPath {"autonomous_system_organization"};

    return [=]()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        auto geoLocator = std::make_shared<::geo::mocks::MockLocator>();
        if (hasASN)
        {
            EXPECT_CALL(*geoLocator, getUint32(testing::_, asnPath)).WillOnce(testing::Return(123u));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getUint32(testing::_, asnPath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasASOrg)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, asOrgPath)).WillOnce(testing::Return("AS Org"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, asOrgPath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        EXPECT_CALL(*geoManager, getLocator(geo::Type::ASN)).WillOnce(testing::Return(geoLocator));
        return getMMDBASNBuilder(geoManager);
    };
}

} // namespace as

// Geo builder
namespace city
{
mapbuildtest::BuilderGetter getBuilderNoLocator()
{
    return []()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        return getMMDBGeoBuilder(geoManager);
    };
}

mapbuildtest::BuilderGetter getBuilderWLocator(bool failLocator = false)
{
    return [=]()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        auto geoLocator = std::make_shared<::geo::mocks::MockLocator>();
        if (failLocator)
        {
            EXPECT_CALL(*geoManager, getLocator(::geo::Type::CITY)).WillOnce(testing::Return(base::Error {"error"}));
        }
        else
        {
            EXPECT_CALL(*geoManager, getLocator(::geo::Type::CITY)).WillOnce(testing::Return(geoLocator));
        }
        return getMMDBGeoBuilder(geoManager);
    };
}

// AS operation
mapbuildtest::BuilderGetter getBuilderLocatorNoResult(bool validIP = true)
{
    return [=]()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        auto geoLocator = std::make_shared<::geo::mocks::MockLocator>();

        ON_CALL(*geoLocator, getString(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        ON_CALL(*geoLocator, getUint32(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        ON_CALL(*geoLocator, getDouble(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));
        ON_CALL(*geoLocator, getAsJson(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"error"}));

        EXPECT_CALL(*geoManager, getLocator(::geo::Type::CITY)).WillOnce(testing::Return(geoLocator));
        return getMMDBGeoBuilder(geoManager);
    };
}

mapbuildtest::BuilderGetter getBuilderLocatorResult(bool hasCity,
                                                    bool hasContinentCode,
                                                    bool hasContinentName,
                                                    bool hasCountryIsoCode,
                                                    bool hasCountryName,
                                                    bool hasLatitude,
                                                    bool hasLongitude,
                                                    bool hasPostalCode,
                                                    bool hasTimeZone,
                                                    bool hasRegionCode,
                                                    bool hasRegionName)
{
    // Path from the root MaxMind object
    const DotPath cityPath {"city.names.en"};
    const DotPath continentCodePath {"continent.code"};
    const DotPath continentNamePath {"continent.names.en"};
    const DotPath countryIsoCodePath {"country.iso_code"};
    const DotPath countryNamePath {"country.names.en"};
    const DotPath latitudePath {"location.latitude"};
    const DotPath longitudePath {"location.longitude"};
    const DotPath postalCodePath {"postal.code"};
    const DotPath timeZonePath {"location.time_zone"};
    const DotPath regionCodePath {"subdivisions.0.iso_code"};
    const DotPath regionNamePath {"subdivisions.0.names.en"};

    return [=]()
    {
        auto geoManager = std::make_shared<::geo::mocks::MockManager>();
        auto geoLocator = std::make_shared<::geo::mocks::MockLocator>();

        if (hasCity)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, cityPath)).WillOnce(testing::Return("City"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, cityPath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasContinentCode)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, continentCodePath)).WillOnce(testing::Return("CC"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, continentCodePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasContinentName)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, continentNamePath)).WillOnce(testing::Return("Continent"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, continentNamePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasCountryIsoCode)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, countryIsoCodePath)).WillOnce(testing::Return("CI"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, countryIsoCodePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasCountryName)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, countryNamePath)).WillOnce(testing::Return("Country"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, countryNamePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasLatitude)
        {
            EXPECT_CALL(*geoLocator, getDouble(testing::_, latitudePath)).WillOnce(testing::Return(1.23));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getDouble(testing::_, latitudePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasLongitude)
        {
            EXPECT_CALL(*geoLocator, getDouble(testing::_, longitudePath)).WillOnce(testing::Return(4.56));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getDouble(testing::_, longitudePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasPostalCode)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, postalCodePath)).WillOnce(testing::Return("12345"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, postalCodePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasTimeZone)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, timeZonePath)).WillOnce(testing::Return("TZ"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, timeZonePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasRegionCode)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, regionCodePath)).WillOnce(testing::Return("RC"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, regionCodePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasRegionName)
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, regionNamePath)).WillOnce(testing::Return("Region"));
        }
        else
        {
            EXPECT_CALL(*geoLocator, getString(testing::_, regionNamePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        EXPECT_CALL(*geoManager, getLocator(::geo::Type::CITY)).WillOnce(testing::Return(geoLocator));
        return getMMDBGeoBuilder(geoManager);
    };
}

} // namespace city

} // namespace

namespace mapbuildtest
{
/*** ASN ***/
INSTANTIATE_TEST_SUITE_P(
    BuilderAS,
    MapBuilderWithDepsTest,
    testing::Values(
        // Only accept a ref with a ip to map an object
        MapDepsT({}, as::getBuilderNoLocator(), FAILURE(expectContext())),
        MapDepsT({makeValue(R"("value")")}, as::getBuilderNoLocator(), FAILURE(expectContext())),
        MapDepsT({makeRef("ref")}, as::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::TEXT))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::KEYWORD))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::INTEGER))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::OBJECT))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::NESTED))),
        MapDepsT({makeRef("ref")}, as::getBuilderWLocator(), SUCCESS(customRefExpected())),
        // #TODO: Fail Locator, Temporary error handling, this should be mandatory
        MapDepsT({makeRef("ref")}, as::getBuilderWLocator(), SUCCESS(expectTypeRef(schemf::Type::IP, true))),
        MapDepsT({makeRef("ref")}, as::getBuilderWLocator(true), SUCCESS(expectTypeRef(schemf::Type::IP, true)))
        // End of test values
        ),
    testNameFormatter<MapBuilderWithDepsTest>("mmdb_asn"));

/*** Geo ***/
INSTANTIATE_TEST_SUITE_P(
    BuilderGeo,
    MapBuilderWithDepsTest,
    testing::Values(
        // Only accept a ref with a ip to map an object
        MapDepsT({}, city::getBuilderNoLocator(), FAILURE()),
        MapDepsT({makeValue(R"("value")")}, city::getBuilderNoLocator(), FAILURE()),
        MapDepsT({makeRef("ref")}, city::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::TEXT, true))),
        MapDepsT({makeRef("ref")}, city::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::KEYWORD, true))),
        MapDepsT({makeRef("ref")}, city::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::INTEGER, true))),
        MapDepsT({makeRef("ref")}, city::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::OBJECT, true))),
        MapDepsT({makeRef("ref")}, city::getBuilderNoLocator(), FAILURE(expectTypeRef(schemf::Type::NESTED, true))),
        MapDepsT({makeRef("ref")}, city::getBuilderWLocator(), SUCCESS(customRefExpected())),
        // #TODO: Fail Locator, Temporary error handling, this should be mandatory
        MapDepsT({makeRef("ref")}, city::getBuilderWLocator(), SUCCESS(expectTypeRef(schemf::Type::IP, true))),
        MapDepsT({makeRef("ref")}, city::getBuilderWLocator(true), SUCCESS(expectTypeRef(schemf::Type::IP, true)))
        // End of test values
        ),
    testNameFormatter<MapBuilderWithDepsTest>("mmdb_city"));

} // namespace mapbuildtest

namespace mapoperatestest
{
/*** ASN ***/
INSTANTIATE_TEST_SUITE_P(
    BuilderOpAs,
    MapOperationWithDepsTest,
    testing::Values(
        // Bad ref
        MapDepsT(
            R"({"ref": {"some":"data"}})", as::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": {}})", as::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": false})", as::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": ["::1"]})", as::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123})", as::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123.34})", as::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(
            R"({"ref": "1.2.3.4"})", as::getBuilderLocatorNoResult(), {makeRef("ref")}, FAILURE(customRefExpected())),
        // No result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderLocatorNoResult(),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        // Partial result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderLocatorResult(false, false),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderLocatorResult(true, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"number": 123})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderLocatorResult(false, true),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"organization": {"name": "AS Org"}})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderLocatorResult(true, true),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"number": 123, "organization": {"name": "AS Org"}})"})))
        // End of test values
        ),
    testNameFormatter<MapOperationWithDepsTest>("mmdb_asn"));

/*** ASN ***/
INSTANTIATE_TEST_SUITE_P(
    BuilderOpGeo,
    MapOperationWithDepsTest,
    testing::Values(
        // Bad ref
        MapDepsT(
            R"({"ref": {"some":"data"}})", city::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": {}})", city::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": false})", city::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": ["::1"]})", city::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123})", city::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123.34})", city::getBuilderWLocator(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(
            R"({"ref": "1.2.3.4"})", city::getBuilderLocatorNoResult(), {makeRef("ref")}, FAILURE(customRefExpected())),
        // No result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 city::getBuilderLocatorNoResult(false),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        // Partial result
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, false, false, false, false, false, false),
            {makeRef("ref")},
            FAILURE(customRefExpected())),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(true, false, false, false, false, false, false, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"city_name": "City"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, true, false, false, false, false, false, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"continent_code": "CC"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, true, false, false, false, false, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"continent_name": "Continent"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, true, false, false, false, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"country_iso_code": "CI"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, true, false, false, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"country_name": "Country"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, true, false, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"location": {"lat": 1.23}})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, false, true, false, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"location": {"lon": 4.56}})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, false, false, true, false, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"postal_code": "12345"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, false, false, false, true, false, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"timezone": "TZ"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, false, false, false, false, true, false),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"region_iso_code": "RC"})"}))),
        MapDepsT(
            R"({"ref": "1.2.3.4"})",
            city::getBuilderLocatorResult(false, false, false, false, false, false, false, false, false, false, true),
            {makeRef("ref")},
            SUCCESS(customRefExpected(json::Json {R"({"region_name": "Region"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 city::getBuilderLocatorResult(true, true, true, true, true, true, true, true, true, true, true),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"(
                    {
                        "city_name": "City",
                        "continent_code": "CC",
                        "continent_name": "Continent",
                        "country_iso_code": "CI",
                        "country_name": "Country",
                        "location": {
                            "lat": 1.23,
                            "lon": 4.56
                        },
                        "postal_code": "12345",
                        "timezone": "TZ",
                        "region_iso_code": "RC",
                        "region_name": "Region"
                    }
                )"})))
        // End of test values
        ),
    testNameFormatter<MapOperationWithDepsTest>("mmdb_asn"));
} // namespace mapoperatestest

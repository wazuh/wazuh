#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/mmdb.hpp"

#include <mmdb/mockHandler.hpp>
#include <mmdb/mockManager.hpp>
#include <mmdb/mockResult.hpp>

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
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectTypeRef(schemf::Type type, bool success = false)
{
    return [=](const BuildersMocks& mocks)
    {
        if (!success)
        {
            EXPECT_CALL(*mocks.ctx, context());
        }
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.schema, getType(DotPath("ref"))).WillRepeatedly(testing::Return(type));
        return None {};
    };
}

auto customRefExpected(const json::Json& value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(false));

        return value;
    };
}

// AS: Builder getters for building test
namespace as
{
mapbuildtest::BuilderGetter getBuilderNoHandler()
{
    return []()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        return getMMDBASNBuilder(mmdbManager);
    };
}

mapbuildtest::BuilderGetter getBuilderWHandler(bool failHandler = false)
{
    return [=]()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        auto mmdbHandler = std::make_shared<::mmdb::MockHandler>();
        if (failHandler)
        {
            EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-asn")).WillOnce(testing::Return(base::Error {"error"}));
        }
        else
        {
            EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-asn")).WillOnce(testing::Return(mmdbHandler));
        }
        return getMMDBASNBuilder(mmdbManager);
    };
}

// AS operation
mapbuildtest::BuilderGetter getBuilderHandlerNoResult(bool validIP = true)
{
    return [=]()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        auto mmdbHandler = std::make_shared<::mmdb::MockHandler>();
        if (!validIP)
        {
            EXPECT_CALL(*mmdbHandler, lookup(testing::_)).WillOnce(testing::Throw(std::runtime_error {"Invalid IP"}));
        }
        else
        {
            auto mmdbResult = std::make_shared<::mmdb::MockResult>();
            EXPECT_CALL(*mmdbResult, hasData()).WillOnce(testing::Return(false));
            EXPECT_CALL(*mmdbHandler, lookup(testing::_)).WillOnce(testing::Return(mmdbResult));
        }
        EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-asn")).WillOnce(testing::Return(mmdbHandler));
        return getMMDBASNBuilder(mmdbManager);
    };
}

mapbuildtest::BuilderGetter getBuilderHandlerResult(bool hasASN, bool hasASOrg)
{
    // Path from the root MaxMind object
    const DotPath asnPath {"autonomous_system_number"};
    const DotPath asOrgPath {"autonomous_system_organization"};

    return [=]()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        auto mmdbHandler = std::make_shared<::mmdb::MockHandler>();
        auto mmdbResult = std::make_shared<::mmdb::MockResult>();
        if (hasASN)
        {
            EXPECT_CALL(*mmdbResult, getUint32(asnPath)).WillOnce(testing::Return(123u));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getUint32(asnPath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasASOrg)
        {
            EXPECT_CALL(*mmdbResult, getString(asOrgPath)).WillOnce(testing::Return("AS Org"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(asOrgPath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        EXPECT_CALL(*mmdbResult, hasData()).WillOnce(testing::Return(true));
        EXPECT_CALL(*mmdbHandler, lookup(testing::_)).WillOnce(testing::Return(mmdbResult));
        EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-asn")).WillOnce(testing::Return(mmdbHandler));
        return getMMDBASNBuilder(mmdbManager);
    };
}

} // namespace as

// Geo builder
namespace geo
{
mapbuildtest::BuilderGetter getBuilderNoHandler()
{
    return []()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        return getMMDBGeoBuilder(mmdbManager);
    };
}

mapbuildtest::BuilderGetter getBuilderWHandler(bool failHandler = false)
{
    return [=]()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        auto mmdbHandler = std::make_shared<::mmdb::MockHandler>();
        if (failHandler)
        {
            EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-city")).WillOnce(testing::Return(base::Error {"error"}));
        }
        else
        {
            EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-city")).WillOnce(testing::Return(mmdbHandler));
        }
        return getMMDBGeoBuilder(mmdbManager);
    };
}

// AS operation
mapbuildtest::BuilderGetter getBuilderHandlerNoResult(bool validIP = true)
{
    return [=]()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        auto mmdbHandler = std::make_shared<::mmdb::MockHandler>();
        if (!validIP)
        {
            EXPECT_CALL(*mmdbHandler, lookup(testing::_)).WillOnce(testing::Throw(std::runtime_error {"Invalid IP"}));
        }
        else
        {
            auto mmdbResult = std::make_shared<::mmdb::MockResult>();
            EXPECT_CALL(*mmdbResult, hasData()).WillOnce(testing::Return(false));
            EXPECT_CALL(*mmdbHandler, lookup(testing::_)).WillOnce(testing::Return(mmdbResult));
        }
        EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-city")).WillOnce(testing::Return(mmdbHandler));
        return getMMDBGeoBuilder(mmdbManager);
    };
}

mapbuildtest::BuilderGetter getBuilderHandlerResult(bool hasCity,
                                                    bool hasContinentCode,
                                                    bool hasContinentName,
                                                    bool hasCountryIsoCode,
                                                    bool hasCountryName,
                                                    bool hasLatitude,
                                                    bool hasLongitude,
                                                    bool hasPostalCode,
                                                    bool hasTimeZone)
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

    return [=]()
    {
        auto mmdbManager = std::make_shared<::mmdb::MockManager>();
        auto mmdbHandler = std::make_shared<::mmdb::MockHandler>();
        auto mmdbResult = std::make_shared<::mmdb::MockResult>();

        if (hasCity)
        {
            EXPECT_CALL(*mmdbResult, getString(cityPath)).WillOnce(testing::Return("City"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(cityPath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasContinentCode)
        {
            EXPECT_CALL(*mmdbResult, getString(continentCodePath)).WillOnce(testing::Return("CC"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(continentCodePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasContinentName)
        {
            EXPECT_CALL(*mmdbResult, getString(continentNamePath)).WillOnce(testing::Return("Continent"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(continentNamePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasCountryIsoCode)
        {
            EXPECT_CALL(*mmdbResult, getString(countryIsoCodePath)).WillOnce(testing::Return("CI"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(countryIsoCodePath))
                .WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasCountryName)
        {
            EXPECT_CALL(*mmdbResult, getString(countryNamePath)).WillOnce(testing::Return("Country"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(countryNamePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasLatitude)
        {
            EXPECT_CALL(*mmdbResult, getDouble(latitudePath)).WillOnce(testing::Return(1.23));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getDouble(latitudePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasLongitude)
        {
            EXPECT_CALL(*mmdbResult, getDouble(longitudePath)).WillOnce(testing::Return(4.56));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getDouble(longitudePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasPostalCode)
        {
            EXPECT_CALL(*mmdbResult, getString(postalCodePath)).WillOnce(testing::Return("12345"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(postalCodePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        if (hasTimeZone)
        {
            EXPECT_CALL(*mmdbResult, getString(timeZonePath)).WillOnce(testing::Return("TZ"));
        }
        else
        {
            EXPECT_CALL(*mmdbResult, getString(timeZonePath)).WillOnce(testing::Return(base::Error {"Not found"}));
        }

        EXPECT_CALL(*mmdbResult, hasData()).WillOnce(testing::Return(true));
        EXPECT_CALL(*mmdbHandler, lookup(testing::_)).WillOnce(testing::Return(mmdbResult));
        EXPECT_CALL(*mmdbManager, getHandler("mm-geolite2-city")).WillOnce(testing::Return(mmdbHandler));
        return getMMDBGeoBuilder(mmdbManager);
    };
}

} // namespace geo

} // namespace

namespace mapbuildtest
{
/*** ASN ***/
INSTANTIATE_TEST_SUITE_P(
    BuilderAS,
    MapBuilderWithDepsTest,
    testing::Values(
        // Only accept a ref with a ip to map an object
        MapDepsT({}, as::getBuilderNoHandler(), FAILURE(expectContext())),
        MapDepsT({makeValue(R"("value")")}, as::getBuilderNoHandler(), FAILURE(expectContext())),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::TEXT))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::KEYWORD))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::INTEGER))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::OBJECT))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::NESTED))),
        MapDepsT({makeRef("ref")}, as::getBuilderWHandler(), SUCCESS(customRefExpected())),
        // #TODO: Fail Handler, Temporary error handling, this should be mandatory
        MapDepsT({makeRef("ref")}, as::getBuilderWHandler(), SUCCESS(expectTypeRef(schemf::Type::IP, true))),
        MapDepsT({makeRef("ref")}, as::getBuilderWHandler(true), SUCCESS(expectTypeRef(schemf::Type::IP, true)))
        // End of test values
        ),
    testNameFormatter<MapBuilderWithDepsTest>("mmdb_asn"));

/*** Geo ***/
INSTANTIATE_TEST_SUITE_P(
    BuilderGeo,
    MapBuilderWithDepsTest,
    testing::Values(
        // Only accept a ref with a ip to map an object
        MapDepsT({}, geo::getBuilderNoHandler(), FAILURE(expectContext())),
        MapDepsT({makeValue(R"("value")")}, geo::getBuilderNoHandler(), FAILURE(expectContext())),
        MapDepsT({makeRef("ref")}, geo::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::TEXT))),
        MapDepsT({makeRef("ref")}, geo::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::KEYWORD))),
        MapDepsT({makeRef("ref")}, geo::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::INTEGER))),
        MapDepsT({makeRef("ref")}, geo::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::OBJECT))),
        MapDepsT({makeRef("ref")}, geo::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::NESTED))),
        MapDepsT({makeRef("ref")}, geo::getBuilderWHandler(), SUCCESS(customRefExpected())),
        // #TODO: Fail Handler, Temporary error handling, this should be mandatory
        MapDepsT({makeRef("ref")}, geo::getBuilderWHandler(), SUCCESS(expectTypeRef(schemf::Type::IP, true))),
        MapDepsT({makeRef("ref")}, geo::getBuilderWHandler(true), SUCCESS(expectTypeRef(schemf::Type::IP, true)))
        // End of test values
        ),
    testNameFormatter<MapBuilderWithDepsTest>("mmdb_geo"));

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
            R"({"ref": {"some":"data"}})", as::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": {}})", as::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": false})", as::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": ["::1"]})", as::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123})", as::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123.34})", as::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(
            R"({"ref": "1.2.3.4"})", as::getBuilderHandlerNoResult(), {makeRef("ref")}, FAILURE(customRefExpected())),
        // No result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderHandlerNoResult(false),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        // Partial result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderHandlerResult(false, false),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderHandlerResult(true, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"number": 123})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderHandlerResult(false, true),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"organization": {"name": "AS Org"}})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 as::getBuilderHandlerResult(true, true),
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
            R"({"ref": {"some":"data"}})", geo::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": {}})", geo::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": false})", geo::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": ["::1"]})", geo::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123})", geo::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": 123.34})", geo::getBuilderWHandler(), {makeRef("ref")}, FAILURE(customRefExpected())),
        MapDepsT(
            R"({"ref": "1.2.3.4"})", geo::getBuilderHandlerNoResult(), {makeRef("ref")}, FAILURE(customRefExpected())),
        // No result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerNoResult(false),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        // Partial result
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, false, false, false, false, false, false),
                 {makeRef("ref")},
                 FAILURE(customRefExpected())),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(true, false, false, false, false, false, false, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"city_name": "City"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, true, false, false, false, false, false, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"continent_code": "CC"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, true, false, false, false, false, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"continent_name": "Continent"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, true, false, false, false, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"country_iso_code": "CI"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, false, true, false, false, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"country_name": "Country"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, false, false, true, false, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"location": {"lat": 1.23}})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, false, false, false, true, false, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"location": {"lon": 4.56}})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, false, false, false, false, true, false),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"postal_code": "12345"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(false, false, false, false, false, false, false, false, true),
                 {makeRef("ref")},
                 SUCCESS(customRefExpected(json::Json {R"({"timezone": "TZ"})"}))),
        MapDepsT(R"({"ref": "1.2.3.4"})",
                 geo::getBuilderHandlerResult(true, true, true, true, true, true, true, true, true),
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
                        "timezone": "TZ"
                    }
                )"})))
        // End of test values
        ),
    testNameFormatter<MapOperationWithDepsTest>("mmdb_asn"));
} // namespace mapoperatestest

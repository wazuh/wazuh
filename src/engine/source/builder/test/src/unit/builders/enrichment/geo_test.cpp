#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>
#include <string>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <base/json.hpp>
#include <base/result.hpp>
#include <geo/ilocator.hpp>
#include <geo/imanager.hpp>
#include <geo/mockLocator.hpp>
#include <geo/mockManager.hpp>

#include "builders/enrichment/enrichment.hpp"

using namespace builder::builders::enrichment;
using namespace geo::mocks;
using namespace testing;

namespace
{

// ─────────────────────────────────────────────────────────────────────────────
// Helper: walk the expression graph and execute every Term on the event
// ─────────────────────────────────────────────────────────────────────────────
bool evalExpression(const base::Expression& expression, const base::Event& event)
{
    if (expression == nullptr)
        return true;

    if (expression->isTerm())
    {
        auto term = expression->getPtr<base::Term<base::EngineOp>>();
        return term->getFn()(event).success();
    }

    if (expression->isChain())
    {
        auto op = expression->getPtr<base::Chain>();
        for (auto& operand : op->getOperands())
            evalExpression(operand, event);
        return true;
    }

    if (expression->isImplication())
    {
        auto op = expression->getPtr<base::Implication>();
        if (evalExpression(op->getOperands()[0], event))
            return evalExpression(op->getOperands()[1], event);
        return false;
    }

    if (expression->isAnd())
    {
        auto op = expression->getPtr<base::And>();
        for (auto& operand : op->getOperands())
        {
            if (!evalExpression(operand, event))
                return false;
        }
        return true;
    }

    if (expression->isOr())
    {
        auto op = expression->getPtr<base::Or>();
        for (auto& operand : op->getOperands())
        {
            if (evalExpression(operand, event))
                return true;
        }
        return false;
    }

    if (expression->isBroadcast())
    {
        auto op = expression->getPtr<base::Broadcast>();
        for (auto& operand : op->getOperands())
            evalExpression(operand, event);
        return true;
    }

    return true;
}

json::Json makeMappingConfig(bool withGeo, bool withAs)
{
    std::string inner = "{";
    bool first = true;
    if (withGeo)
    {
        inner += R"("geo_field": "source.geo")";
        first = false;
    }
    if (withAs)
    {
        if (!first)
            inner += ",";
        inner += R"("as_field": "source.as")";
    }
    inner += "}";

    auto doc = fmt::format(R"({{"source.ip": {}}})", inner);
    return json::Json {doc.c_str()};
}

base::Event makeEvent(const std::string& ip)
{
    return std::make_shared<json::Json>(
        fmt::format(R"({{"source":{{"ip":"{}"}}, "event":{{"original":"test"}}}})", ip).c_str());
}

base::Event makeEventNoIp()
{
    return std::make_shared<json::Json>(R"({"source":{}, "event":{"original":"test"}})");
}

base::Event makeEventNonStringIp()
{
    return std::make_shared<json::Json>(R"({"source":{"ip": 12345}, "event":{"original":"test"}})");
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Test: Build a geo enrichment operation using a valid configuration
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, BuildValidConfiguration)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);

    // Building should not throw
    auto [expr, name] = enrichBuilder(false);
    ASSERT_NE(expr, nullptr);
    EXPECT_FALSE(name.empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Enrich an event when the source IP has Geo information
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, EnrichWithGeoData)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    // City locator returns geo data
    EXPECT_CALL(*mockCity, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "city.names.en")
                    return std::string {"London"};
                if (path.str() == "country.iso_code")
                    return std::string {"GB"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockCity, getDouble(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<double>
            {
                if (path.str() == "location.latitude")
                    return 51.5074;
                if (path.str() == "location.longitude")
                    return -0.1278;
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });

    // ASN locator returns no data (only geo configured)
    auto config = makeMappingConfig(true, false);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent("1.2.3.4");
    evalExpression(expr, event);

    // Verify geo fields were set
    std::string cityName;
    EXPECT_EQ(event->getString(cityName, "/source/geo/city_name"), json::RetGet::Success);
    EXPECT_EQ(cityName, "London");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Enrich an event when the source IP has ASN information
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, EnrichWithAsnData)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    // ASN locator returns data
    EXPECT_CALL(*mockAsn, getUint32(std::string("8.8.8.8"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<uint32_t>
            {
                if (path.str() == "autonomous_system_number")
                    return uint32_t {15169};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockAsn, getString(std::string("8.8.8.8"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "autonomous_system_organization")
                    return std::string {"Google LLC"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });

    // Only ASN configured
    auto config = makeMappingConfig(false, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent("8.8.8.8");
    evalExpression(expr, event);

    // Verify AS fields were set
    std::string orgName;
    EXPECT_EQ(event->getString(orgName, "/source/as/organization/name"), json::RetGet::Success);
    EXPECT_EQ(orgName, "Google LLC");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Enrich an event when the source IP has both Geo and ASN information
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, EnrichWithBothGeoAndAsn)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "city.names.en")
                    return std::string {"Berlin"};
                if (path.str() == "country.iso_code")
                    return std::string {"DE"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockCity, getDouble(std::string("1.2.3.4"), _))
        .WillRepeatedly(Return(geo::ErrorCode::DATA_ENTRY_EMPTY));

    EXPECT_CALL(*mockAsn, getUint32(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<uint32_t>
            {
                if (path.str() == "autonomous_system_number")
                    return uint32_t {3320};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockAsn, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "autonomous_system_organization")
                    return std::string {"Deutsche Telekom AG"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent("1.2.3.4");
    evalExpression(expr, event);

    // Verify both Geo and AS data set
    std::string cityName;
    EXPECT_EQ(event->getString(cityName, "/source/geo/city_name"), json::RetGet::Success);
    EXPECT_EQ(cityName, "Berlin");

    std::string orgName;
    EXPECT_EQ(event->getString(orgName, "/source/as/organization/name"), json::RetGet::Success);
    EXPECT_EQ(orgName, "Deutsche Telekom AG");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Handle an event where the configured source IP field is missing
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, MissingSourceIpField)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(false);

    // Event without the source.ip field
    auto event = makeEventNoIp();
    evalExpression(expr, event);

    // Verify no geo/as fields were set
    std::string dummy;
    EXPECT_NE(event->getString(dummy, "/source/geo/city_name"), json::RetGet::Success);
    EXPECT_NE(event->getString(dummy, "/source/as/organization/name"), json::RetGet::Success);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Handle an event where the configured source IP field exists but is not a string
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, NonStringSourceIpField)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(false);

    // Event with numeric IP value
    auto event = makeEventNonStringIp();
    evalExpression(expr, event);

    // No enrichment should be applied
    std::string dummy;
    EXPECT_NE(event->getString(dummy, "/source/geo/city_name"), json::RetGet::Success);
    EXPECT_NE(event->getString(dummy, "/source/as/organization/name"), json::RetGet::Success);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Handle a valid source IP that has no Geo or ASN information
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, NoGeoOrAsnDataForIp)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    // Both locators return no data
    EXPECT_CALL(*mockCity, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockAsn, getUint32(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockAsn, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent("10.0.0.1");
    evalExpression(expr, event);

    // No enrichment should be applied
    std::string dummy;
    EXPECT_NE(event->getString(dummy, "/source/geo/city_name"), json::RetGet::Success);
    EXPECT_NE(event->getString(dummy, "/source/as/organization/name"), json::RetGet::Success);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Handle missing or unavailable Geo/ASN locator dependencies
// ─────────────────────────────────────────────────────────────────────────────
TEST(GeoEnrichmentTest, UnavailableAsnLocator)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(geo::ErrorCode::DB_NOT_AVAILABLE)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);

    EXPECT_THROW(enrichBuilder(false), std::runtime_error);
}

TEST(GeoEnrichmentTest, UnavailableCityLocator)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(geo::ErrorCode::DB_NOT_AVAILABLE)));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);

    EXPECT_THROW(enrichBuilder(false), std::runtime_error);
}

// =============================================================================
// Tests with isTestMode=true (trace messages in geo enrichment)
// =============================================================================

TEST(GeoEnrichmentTest, TestModeSuccessBothGeoAndAsn)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "city.names.en")
                    return std::string {"Berlin"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::DATA_ENTRY_EMPTY));

    EXPECT_CALL(*mockAsn, getUint32(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<uint32_t>
            {
                if (path.str() == "autonomous_system_number")
                    return uint32_t {3320};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockAsn, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "autonomous_system_organization")
                    return std::string {"Deutsche Telekom AG"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("1.2.3.4");
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeSuccessOnlyGeo)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "city.names.en")
                    return std::string {"Berlin"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::DATA_ENTRY_EMPTY));
    EXPECT_CALL(*mockAsn, getUint32(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockAsn, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("1.2.3.4");
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeSuccessOnlyAsn)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));

    EXPECT_CALL(*mockAsn, getUint32(std::string("8.8.8.8"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<uint32_t>
            {
                if (path.str() == "autonomous_system_number")
                    return uint32_t {15169};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockAsn, getString(std::string("8.8.8.8"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "autonomous_system_organization")
                    return std::string {"Google LLC"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });

    auto config = makeMappingConfig(false, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("8.8.8.8");
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeNoDataForIp)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockAsn, getUint32(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockAsn, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("10.0.0.1");
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeMissingSourceIp)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    auto config = makeMappingConfig(true, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEventNoIp();
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeOnlyGeoConfigured)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(std::string("1.2.3.4"), _))
        .WillRepeatedly(
            [](const std::string&, const DotPath& path) -> geo::Result<std::string>
            {
                if (path.str() == "city.names.en")
                    return std::string {"Paris"};
                return geo::ErrorCode::DATA_ENTRY_EMPTY;
            });
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::DATA_ENTRY_EMPTY));

    auto config = makeMappingConfig(true, false);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("1.2.3.4");
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeOnlyGeoConfiguredNoData)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockCity, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockCity, getDouble(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));

    auto config = makeMappingConfig(true, false);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("10.0.0.1");
    evalExpression(expr, event);
}

TEST(GeoEnrichmentTest, TestModeOnlyAsnConfiguredNoData)
{
    auto mockManager = std::make_shared<MockManager>();
    auto mockCity = std::make_shared<MockLocator>();
    auto mockAsn = std::make_shared<MockLocator>();

    EXPECT_CALL(*mockManager, getLocator(geo::Type::CITY))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockCity)));
    EXPECT_CALL(*mockManager, getLocator(geo::Type::ASN))
        .WillOnce(Return(geo::Result<std::shared_ptr<geo::ILocator>>(mockAsn)));

    EXPECT_CALL(*mockAsn, getUint32(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));
    EXPECT_CALL(*mockAsn, getString(_, _)).WillRepeatedly(Return(geo::ErrorCode::IP_NOT_FOUND));

    auto config = makeMappingConfig(false, true);
    auto enrichBuilder = getGeoEnrichmentBuilder(mockManager, config);
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent("10.0.0.1");
    evalExpression(expr, event);
}

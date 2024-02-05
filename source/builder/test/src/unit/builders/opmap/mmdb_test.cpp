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

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderWithDepsTest,
    testing::Values(
        /*** ASN ***/
        // Only accept a ref with a ip to map an object
        MapDepsT({}, as::getBuilderNoHandler(), FAILURE(expectContext())),
        MapDepsT({makeValue(R"("value")")}, as::getBuilderNoHandler(), FAILURE(expectContext())),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::TEXT))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::KEYWORD))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::INTEGER))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::OBJECT))),
        MapDepsT({makeRef("ref")}, as::getBuilderNoHandler(), FAILURE(expectTypeRef(schemf::Type::NESTED))),
        MapDepsT({makeRef("ref")}, as::getBuilderWHandler(), SUCCESS(customRefExpected())),
        // TODO: Fail Handler, Temporary error handling, this should be mandatory
        MapDepsT({makeRef("ref")}, as::getBuilderWHandler(), SUCCESS(expectTypeRef(schemf::Type::IP, true))),
        MapDepsT({makeRef("ref")}, as::getBuilderWHandler(true), SUCCESS(expectTypeRef(schemf::Type::IP, true)))
        // End of test values
        ),
    testNameFormatter<MapBuilderWithDepsTest>("mmdb_asn"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationWithDepsTest,
    testing::Values(
        /*** ASN ***/
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
} // namespace mapoperatestest

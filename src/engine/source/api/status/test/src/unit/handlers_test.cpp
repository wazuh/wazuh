#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <api/status/handlers.hpp>
#include <base/syncStatus.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/status.pb.h>

#include <cmsync/mockCMSync.hpp>
#include <geo/mockManager.hpp>
#include <iocsync/mockIocSync.hpp>

namespace eStatus = ::com::wazuh::api::engine::status;

using cm::sync::mocks::MockCMSync;
using geo::mocks::MockManager;
using ioc::sync::mocks::MockIocSync;

// ─── Test Fixture ───────────────────────────────────────────────────────────

class StatusHandlerTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockCMSync> m_mockCmSync;
    std::shared_ptr<MockIocSync> m_mockIocSync;
    std::shared_ptr<MockManager> m_mockGeo;

    void SetUp() override
    {
        m_mockCmSync = std::make_shared<MockCMSync>();
        m_mockIocSync = std::make_shared<MockIocSync>();
        m_mockGeo = std::make_shared<MockManager>();
    }

    httplib::Response callHandler()
    {
        auto handler = api::status::handlers::getStatus(m_mockCmSync, m_mockIocSync, m_mockGeo);
        httplib::Request req;
        httplib::Response res;
        handler(req, res);
        return res;
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

// All resources available and enabled → ready = true
TEST_F(StatusHandlerTest, AllReady)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "hash1", 1759190400},
            {"custom", true, true, base::SyncStatus::READY, "hash2", 1759190400},
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", true, base::SyncStatus::READY, "h1", 1759190400},
            {"urls_domain", true, base::SyncStatus::READY, "h2", 1759190400},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::READY, "g1", 1759190400},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    EXPECT_EQ(res.status, httplib::StatusCode::OK_200);

    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_TRUE(response.ready());
    EXPECT_EQ(response.spaces().size(), 2);
    EXPECT_EQ(response.ioc().size(), 2);
    EXPECT_EQ(response.geo().size(), 2);
}

// Enabled space unavailable → ready = false
TEST_F(StatusHandlerTest, EnabledSpaceUnavailable)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", false, true, base::SyncStatus::UPDATING, "", 0}, // enabled but not available
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", true, base::SyncStatus::READY, "h1", 1759190400},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::READY, "g1", 1759190400},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    EXPECT_EQ(res.status, httplib::StatusCode::OK_200);

    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_FALSE(response.ready());
    EXPECT_EQ(response.spaces().at("standard").status(), "updating");
}

// Disabled space unavailable → ready = true (disabled spaces ignored)
TEST_F(StatusHandlerTest, DisabledSpaceIgnoredForStatus)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "hash1", 1759190400},
            {"custom", false, false, base::SyncStatus::READY, "", 0}, // disabled & unavailable
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", true, base::SyncStatus::READY, "h1", 1759190400},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::READY, "g1", 1759190400},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_TRUE(response.ready());
    // Disabled space is still reported
    EXPECT_TRUE(response.spaces().contains("custom"));
    EXPECT_FALSE(response.spaces().at("custom").available());
    EXPECT_FALSE(response.spaces().at("custom").enabled());
}

// IOC unavailable → ready = false
TEST_F(StatusHandlerTest, IocUnavailable)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "hash1", 1759190400},
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", false, base::SyncStatus::FAILED, "", 0}, // unavailable
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::READY, "g1", 1759190400},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_FALSE(response.ready());
    EXPECT_EQ(response.ioc().at("connection").status(), "failed");
}

// Geo unavailable → ready = false
TEST_F(StatusHandlerTest, GeoUnavailable)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "hash1", 1759190400},
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", true, base::SyncStatus::READY, "h1", 1759190400},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", false, base::SyncStatus::UPDATING, "", 0}, // geo unavailable
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_FALSE(response.ready());
}

// Partially synchronized: space running but available → ready = true
TEST_F(StatusHandlerTest, PartiallySynchronizedStillReady)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::UPDATING, "hash1", 1759190400}, // running but available
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", true, base::SyncStatus::UPDATING, "h1", 1759190400}, // running but available
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::UPDATING, "g1", 1759190400}, // running but available
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    // Running doesn't affect readiness — only available matters
    EXPECT_TRUE(response.ready());
}

// Response includes correct field values
TEST_F(StatusHandlerTest, ResponseFieldValues)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "abc123", 1759190400},
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"hashes_md5", true, base::SyncStatus::READY, "md5hash", 1759190500},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"asn", true, base::SyncStatus::READY, "asnhash", 1759190600},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    // Check space fields
    const auto& space = response.spaces().at("standard");
    EXPECT_TRUE(space.available());
    EXPECT_TRUE(space.enabled());
    EXPECT_EQ(space.status(), "ready");
    EXPECT_EQ(space.hash(), "abc123");
    EXPECT_EQ(space.last_successful_update(), 1759190400);

    // Check IOC fields
    const auto& ioc = response.ioc().at("hashes_md5");
    EXPECT_TRUE(ioc.available());
    EXPECT_EQ(ioc.status(), "ready");
    EXPECT_EQ(ioc.hash(), "md5hash");
    EXPECT_EQ(ioc.last_successful_update(), 1759190500);

    // Check Geo fields
    const auto& geo_entry = response.geo().at("asn");
    EXPECT_TRUE(geo_entry.available());
    EXPECT_EQ(geo_entry.status(), "ready");
    EXPECT_EQ(geo_entry.hash(), "asnhash");
    EXPECT_EQ(geo_entry.last_successful_update(), 1759190600);
}

// ─── Additional tests: gaps / bug hunting ─────────────────────────────────────

// One of the providers is destroyed (weak_ptr expired) → 500 Internal Server Error.
// This error path is currently untested.
TEST_F(StatusHandlerTest, ProviderUnavailableReturns500)
{
    // Build the handler while all providers are alive, then destroy one before invoking.
    auto handler = api::status::handlers::getStatus(m_mockCmSync, m_mockIocSync, m_mockGeo);

    m_mockGeo.reset(); // geo provider gone

    httplib::Request req;
    httplib::Response res;
    handler(req, res);

    EXPECT_EQ(res.status, httplib::StatusCode::InternalServerError_500);
}

// No IOC databases configured at all (empty vector) → readiness is NOT lowered.
// This documents/exposes the current semantics: with zero IOC resources the engine
// reports ready=true even though no IOC data is available for event processing.
TEST_F(StatusHandlerTest, EmptyIocStillReady)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "hash1", 1759190400},
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus()).WillOnce(::testing::Return(std::vector<IocTypeStatus> {}));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::READY, "g1", 1759190400},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_EQ(response.ioc().size(), 0);
    // NOTE: this is the current behavior. If "no IOC db available" should block
    // readiness, this assertion (and the handler) need to change.
    EXPECT_TRUE(response.ready());
}

// Everything empty (no spaces, no ioc, no geo) → ready=true.
// Degenerate/unconfigured state still reports ready.
TEST_F(StatusHandlerTest, AllEmptyStillReady)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus()).WillOnce(::testing::Return(std::vector<SpaceStatus> {}));
    EXPECT_CALL(*m_mockIocSync, getIocStatus()).WillOnce(::testing::Return(std::vector<IocTypeStatus> {}));
    EXPECT_CALL(*m_mockGeo, getGeoStatus()).WillOnce(::testing::Return(std::vector<GeoDbStatus> {}));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_TRUE(response.ready());
    EXPECT_EQ(response.spaces().size(), 0);
    EXPECT_EQ(response.ioc().size(), 0);
    EXPECT_EQ(response.geo().size(), 0);
}

// Multiple categories unavailable at once → ready=false and every resource is still reported.
// "The endpoint must report the current state even while a resource is unavailable."
TEST_F(StatusHandlerTest, MultipleUnavailableStillReportsAll)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", false, true, base::SyncStatus::FAILED, "", 0},
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", false, base::SyncStatus::FAILED, "", 0},
            {"urls_domain", true, base::SyncStatus::READY, "h2", 1759190400},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", false, base::SyncStatus::UPDATING, "", 0},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    EXPECT_EQ(res.status, httplib::StatusCode::OK_200);
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_FALSE(response.ready());
    // All resources are still present in the response even though some are unavailable.
    EXPECT_TRUE(response.spaces().contains("standard"));
    EXPECT_TRUE(response.ioc().contains("connection"));
    EXPECT_TRUE(response.ioc().contains("urls_domain"));
    EXPECT_TRUE(response.geo().contains("city"));
    EXPECT_TRUE(response.geo().contains("asn"));
}

// A disabled-but-available space alongside an enabled+available space keeps readiness true
// (mirror of the disabled-ignored requirement, from the available side).
TEST_F(StatusHandlerTest, DisabledAvailableSpaceStillReady)
{
    using namespace cm::sync;
    using namespace ioc::sync;
    using namespace geo;

    EXPECT_CALL(*m_mockCmSync, getSpacesStatus())
        .WillOnce(::testing::Return(std::vector<SpaceStatus> {
            {"standard", true, true, base::SyncStatus::READY, "hash1", 1759190400},
            {"custom", true, false, base::SyncStatus::READY, "hash2", 1759190400}, // available but disabled
        }));

    EXPECT_CALL(*m_mockIocSync, getIocStatus())
        .WillOnce(::testing::Return(std::vector<IocTypeStatus> {
            {"connection", true, base::SyncStatus::READY, "h1", 1759190400},
        }));

    EXPECT_CALL(*m_mockGeo, getGeoStatus())
        .WillOnce(::testing::Return(std::vector<GeoDbStatus> {
            {"city", true, base::SyncStatus::READY, "g1", 1759190400},
            {"asn", true, base::SyncStatus::READY, "g2", 1759190400},
        }));

    auto res = callHandler();
    auto parsed = eMessage::eMessageFromJson<eStatus::StatusGet_Response>(res.body);
    ASSERT_FALSE(std::holds_alternative<base::Error>(parsed));
    const auto& response = std::get<eStatus::StatusGet_Response>(parsed);

    EXPECT_TRUE(response.ready());
    EXPECT_FALSE(response.spaces().at("custom").enabled());
    EXPECT_TRUE(response.spaces().at("custom").available());
}

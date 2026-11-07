// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <string_view>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <rawevtindexer/raweventindexer.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

using ::testing::Eq;
using ::testing::StrictMock;

static_assert(wiconnector::RAW_EVENTS_INDEX == "wazuh-events-raw-v5", "operator contract: the raw events index name");

class RawEventIndexerUnitTest : public ::testing::Test
{
protected:
    std::shared_ptr<StrictMock<wiconnector::mocks::MockWIndexerConnector>> m_connector;

    void SetUp() override { m_connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>(); }
};

TEST_F(RawEventIndexerUnitTest, ConstructorThrowsIfConnectorIsExpired)
{
    std::weak_ptr<wiconnector::IWIndexerConnector> expired;
    EXPECT_THROW((void)raweventindexer::RawEventIndexer(expired), std::runtime_error);
}

TEST_F(RawEventIndexerUnitTest, ConstructorAlwaysStartsDisabled)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    EXPECT_FALSE(indexer.isEnabled());
}

TEST_F(RawEventIndexerUnitTest, EnableDisableTogglesState)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    EXPECT_FALSE(indexer.isEnabled());

    indexer.enable();
    EXPECT_TRUE(indexer.isEnabled());

    indexer.disable();
    EXPECT_FALSE(indexer.isEnabled());
}

TEST_F(RawEventIndexerUnitTest, IndexConstStringWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    indexer.enable();

    const std::string payload {"payload"};
    EXPECT_CALL(*m_connector, index(Eq(wiconnector::RAW_EVENTS_INDEX), Eq(std::string_view {"payload"})));
    indexer.index(payload);
    EXPECT_EQ(payload, "payload");
}

TEST_F(RawEventIndexerUnitTest, IndexRvalueStringWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    indexer.enable();

    EXPECT_CALL(*m_connector, index(Eq(wiconnector::RAW_EVENTS_INDEX), Eq(std::string_view {"payload-rv"})));
    indexer.index(std::string {"payload-rv"});
}

TEST_F(RawEventIndexerUnitTest, IndexDoesNothingWhenDisabled)
{
    raweventindexer::RawEventIndexer indexer(m_connector);

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).Times(0);
    const std::string payload {"payload"};
    indexer.index(payload);
    indexer.index(std::string {"payload"});
    indexer.index("payload");
    indexer.index(std::string_view {"payload"});
}

TEST_F(RawEventIndexerUnitTest, IndexCStringNullOrEmptyReturnsEarly)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    indexer.enable();

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).Times(0);
    indexer.index(static_cast<const char*>(nullptr));
    indexer.index("");
}

TEST_F(RawEventIndexerUnitTest, IndexStringViewEmptyReturnsEarly)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    indexer.enable();

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).Times(0);
    indexer.index(std::string_view {});
}

TEST_F(RawEventIndexerUnitTest, IndexCStringWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    indexer.enable();

    EXPECT_CALL(*m_connector, index(Eq(wiconnector::RAW_EVENTS_INDEX), Eq(std::string_view {"payload-c"})));
    indexer.index("payload-c");
}

TEST_F(RawEventIndexerUnitTest, IndexStringViewWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector);
    indexer.enable();

    EXPECT_CALL(*m_connector, index(Eq(wiconnector::RAW_EVENTS_INDEX), Eq(std::string_view {"payload-sv"})));
    indexer.index(std::string_view {"payload-sv"});
}

TEST_F(RawEventIndexerUnitTest, IndexNoThrowIfConnectorExpiresAfterConstruction)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    raweventindexer::RawEventIndexer indexer(connector);
    indexer.enable();

    connector.reset();
    EXPECT_NO_THROW(indexer.index(std::string {"payload"}));
}

TEST_F(RawEventIndexerUnitTest, OnRemoteConfigEnablesAndDisablesIndexer)
{
    raweventindexer::RawEventIndexer indexer(m_connector);

    EXPECT_NO_THROW(indexer.hotReloadConf(json::Json("true")));
    EXPECT_TRUE(indexer.isEnabled());

    EXPECT_NO_THROW(indexer.hotReloadConf(json::Json("false")));
    EXPECT_FALSE(indexer.isEnabled());
}

TEST_F(RawEventIndexerUnitTest, OnRemoteConfigRejectsNonBooleanPayload)
{
    raweventindexer::RawEventIndexer indexer(m_connector);

    EXPECT_THROW(indexer.hotReloadConf(json::Json("\"true\"")), std::invalid_argument);
    EXPECT_FALSE(indexer.isEnabled());
}

namespace
{
/// Hand-written connector: records where the body's bytes live, which a gmock action cannot show (it copies).
class RecordingConnector final : public wiconnector::IWIndexerConnector
{
public:
    std::string lastIndex;
    const char* lastDataPtr {nullptr};

    void index(std::string index, std::string data) override
    {
        lastIndex = std::move(index);
        lastDataPtr = data.data();
    }
    json::Json getEngineRemoteConfig() override { return json::Json {}; }
    uint64_t getQueueSize() override { return 0; }
    uint64_t getDroppedEvents() override { return 0; }
    double getQueueUsagePercent() override { return 0.0; }
};
} // namespace

// The worker's payload is a temporary: it must reach the connector without a copy
TEST(RawEventIndexerMoveTest, RvalueBodyIsMovedToConnector)
{
    auto connector = std::make_shared<RecordingConnector>();
    raweventindexer::RawEventIndexer indexer(connector);
    indexer.enable();

    std::string body(4096, 'x'); // beyond any small-string buffer
    const auto* bodyPtr = body.data();
    indexer.index(std::move(body));

    EXPECT_EQ(connector->lastIndex, wiconnector::RAW_EVENTS_INDEX);
    EXPECT_EQ(connector->lastDataPtr, bodyPtr);
}

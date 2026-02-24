#include <memory>
#include <string_view>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <rawevtindexer/raweventindexer.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

using ::testing::Eq;
using ::testing::StrictMock;

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

TEST_F(RawEventIndexerUnitTest, ConstructorRespectsInitialEnabledState)
{
    raweventindexer::RawEventIndexer disabled(m_connector, "wazuh-events-raw-v5", false);
    EXPECT_FALSE(disabled.isEnabled());

    raweventindexer::RawEventIndexer enabled(m_connector, "wazuh-events-raw-v5", true);
    EXPECT_TRUE(enabled.isEnabled());
}

TEST_F(RawEventIndexerUnitTest, EnableDisableTogglesState)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "wazuh-events-raw-v5", false);
    EXPECT_FALSE(indexer.isEnabled());

    indexer.enable();
    EXPECT_TRUE(indexer.isEnabled());

    indexer.disable();
    EXPECT_FALSE(indexer.isEnabled());
}

TEST_F(RawEventIndexerUnitTest, IndexStringWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", true);

    EXPECT_CALL(*m_connector, index(Eq(std::string_view {"custom-raw-index"}), Eq(std::string_view {"payload"})));
    indexer.index(std::string {"payload"});
}

TEST_F(RawEventIndexerUnitTest, IndexDoesNothingWhenDisabled)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", false);

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).Times(0);
    indexer.index(std::string {"payload"});
    indexer.index("payload");
    indexer.index(std::string_view {"payload"});
}

TEST_F(RawEventIndexerUnitTest, IndexCStringNullOrEmptyReturnsEarly)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", true);

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).Times(0);
    indexer.index(static_cast<const char*>(nullptr));
    indexer.index("");
}

TEST_F(RawEventIndexerUnitTest, IndexStringViewEmptyReturnsEarly)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", true);

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).Times(0);
    indexer.index(std::string_view {});
}

TEST_F(RawEventIndexerUnitTest, IndexCStringWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", true);

    EXPECT_CALL(*m_connector, index(Eq(std::string_view {"custom-raw-index"}), Eq(std::string_view {"payload-c"})));
    indexer.index("payload-c");
}

TEST_F(RawEventIndexerUnitTest, IndexStringViewWhenEnabledCallsConnector)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", true);

    EXPECT_CALL(*m_connector, index(Eq(std::string_view {"custom-raw-index"}), Eq(std::string_view {"payload-sv"})));
    indexer.index(std::string_view {"payload-sv"});
}

TEST_F(RawEventIndexerUnitTest, IndexSwallowsConnectorExceptions)
{
    raweventindexer::RawEventIndexer indexer(m_connector, "custom-raw-index", true);

    EXPECT_CALL(*m_connector, index(::testing::_, ::testing::_)).WillOnce(::testing::Throw(std::runtime_error("boom")));
    EXPECT_NO_THROW(indexer.index(std::string {"payload"}));
}

TEST_F(RawEventIndexerUnitTest, IndexNoThrowIfConnectorExpiresAfterConstruction)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    raweventindexer::RawEventIndexer indexer(connector, "custom-raw-index", true);

    connector.reset();
    EXPECT_NO_THROW(indexer.index(std::string {"payload"}));
}

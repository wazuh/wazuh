#ifndef _INDEXER_CONNECTOR_MOCK_ICONNECTOR_HPP
#define _INDEXER_CONNECTOR_MOCK_ICONNECTOR_HPP

#include <gmock/gmock.h>

#include <indexerConnector/iindexerconnector.hpp>

namespace indexerconnector::mocks
{

class MockIConnector : public IIndexerConnector
{
public:
    MOCK_METHOD(void, publish, (const std::string& message), (override));
};

} // namespace indexerconnector::mocks
#endif // _INDEXER_CONNECTOR_MOCK_ICONNECTOR_HPP

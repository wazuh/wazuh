#ifndef _MOCKS_WINDEXER_CONNECTOR_HPP
#define _MOCKS_WINDEXER_CONNECTOR_HPP

#include <gmock/gmock.h>
#include <wiconnector/iwindexerconnector.hpp>

namespace wiconnector::mocks
{
class MockWIndexerConnector : public ::wiconnector::IWIndexerConnector
{
public:
    MOCK_METHOD(void, index, (std::string_view index, std::string_view data), (override));
    MOCK_METHOD(PolicyResources, getPolicy, (std::string_view space), (override));
    MOCK_METHOD(std::string, getPolicyHash, (std::string_view space), (override));
    MOCK_METHOD(bool, existsPolicy, (std::string_view space), (override));
    MOCK_METHOD(bool, existsIndex, (std::string_view indexName), (override));
    MOCK_METHOD(std::vector<json::Json>, query, (std::string_view indexName, std::string_view query, std::size_t maxResults), (override));
    MOCK_METHOD(std::size_t, getIndexDocumentCount, (std::string_view indexName), (override));
};
} // namespace wiconnector::mocks

#endif // _MOCKS_WINDEXER_CONNECTOR_HPP

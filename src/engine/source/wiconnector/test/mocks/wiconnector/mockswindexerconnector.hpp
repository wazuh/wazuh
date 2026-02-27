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
    MOCK_METHOD(bool, existsIocDataIndex, (), (override));
    MOCK_METHOD(std::vector<std::string>, getDefaultIocTypes, (), (override));
    MOCK_METHOD((std::unordered_map<std::string, std::string>), getIocTypeHashes, (), (override));
    MOCK_METHOD(std::size_t,
                streamIocsByType,
                (std::string_view iocType, std::size_t batchSize, const IocRecordCallback& onIoc),
                (override));
};
} // namespace wiconnector::mocks

#endif // _MOCKS_WINDEXER_CONNECTOR_HPP

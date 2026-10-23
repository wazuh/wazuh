// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef MOCK_INDEXER_CONNECTOR_ASYNC_HPP
#define MOCK_INDEXER_CONNECTOR_ASYNC_HPP

#include <gmock/gmock.h>

#include <wiconnector/iindexerConnectorAsync.hpp>

namespace wiconnector::mocks
{

class MockIndexerConnectorAsync : public ::wiconnector::IIndexerConnectorAsync
{
public:
    MOCK_METHOD(void, indexDataStream, (std::string_view index, std::string_view data), (override));
    MOCK_METHOD(uint64_t, getQueueSize, (), (const, override));
    MOCK_METHOD(uint64_t, getDroppedEvents, (), (const, override));
    MOCK_METHOD(nlohmann::json,
                search,
                (std::string_view index,
                 std::size_t size,
                 const nlohmann::json& query,
                 const std::optional<nlohmann::json>& source),
                (override));
};

} // namespace wiconnector::mocks

#endif // MOCK_INDEXER_CONNECTOR_ASYNC_HPP

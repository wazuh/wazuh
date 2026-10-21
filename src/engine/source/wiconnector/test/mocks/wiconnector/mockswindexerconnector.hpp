// SPDX-License-Identifier: AGPL-3.0-or-later
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
    MOCK_METHOD(uint64_t, getQueueSize, (), (override));
    MOCK_METHOD(uint64_t, getDroppedEvents, (), (override));
    MOCK_METHOD(json::Json, getEngineRemoteConfig, (), (override));
};
} // namespace wiconnector::mocks

#endif // _MOCKS_WINDEXER_CONNECTOR_HPP

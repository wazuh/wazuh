#ifndef _SOCKIFACE_MOCK_SOCK_HANDLER_HPP
#define _SOCKIFACE_MOCK_SOCK_HANDLER_HPP

#include <gmock/gmock.h>

#include <sockiface/isockHandler.hpp>

class MockSockHandler : public sockiface::ISockHandler
{
public:
    MOCK_METHOD(uint32_t, getMaxMsgSize, (), (const, noexcept, override));
    MOCK_METHOD(std::string, getPath, (), (const, noexcept, override));
    MOCK_METHOD(void, socketConnect, (), (override));
    MOCK_METHOD(void, socketDisconnect, (), (override));
    MOCK_METHOD(bool, isConnected, (), (const, noexcept, override));
    MOCK_METHOD(SendRetval, sendMsg, (const std::string& msg), (override));
    MOCK_METHOD(std::vector<char>, recvMsg, (), (override));
};
#endif // _SOCKIFACE_MOCK_SOCK_HANDLER_HPP

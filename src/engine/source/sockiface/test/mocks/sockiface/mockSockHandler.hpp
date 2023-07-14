#ifndef _SOCKIFACE_MOCK_SOCK_HANDLER_HPP
#define _SOCKIFACE_MOCK_SOCK_HANDLER_HPP

#include <gmock/gmock.h>

#include <sockiface/isockHandler.hpp>

namespace sockiface::mocks
{

constexpr ISockHandler::SendRetval successSendMsgRes()
{
    return ISockHandler::SendRetval::SUCCESS;
}

constexpr ISockHandler::SendRetval sizeZeroSendMsgRes()
{
    return ISockHandler::SendRetval::SIZE_ZERO;
}

constexpr ISockHandler::SendRetval sizeTooLongSendMsgRes()
{
    return ISockHandler::SendRetval::SIZE_TOO_LONG;
}

constexpr ISockHandler::SendRetval socketErrorSendMsgRes()
{
    return ISockHandler::SendRetval::SOCKET_ERROR;
}

inline std::vector<char> recvMsgRes(const std::string& res)
{
    std::vector<char> resVec(res.begin(), res.end());
    resVec.push_back('\0');
    return resVec;
}

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

} // namespace sockiface::mocks
#endif // _SOCKIFACE_MOCK_SOCK_HANDLER_HPP

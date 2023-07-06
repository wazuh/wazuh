#include "unixDatagram.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace sockiface
{

ISockHandler::SendRetval unixDatagram::sendMsg(const std::string& msg)
{
    auto result {SendRetval::SOCKET_ERROR};
    auto payloadSize {msg.size()};

    // Validate
    if (!isConnected())
    {
        socketConnect();
    }

    if (0 >= payloadSize)
    {
        result = SendRetval::SIZE_ZERO;
    }
    else if (getMaxMsgSize() < payloadSize)
    {
        result = SendRetval::SIZE_TOO_LONG;
    }
    else
    {
        // Send the message
        const auto sent {send(getFD(), msg.data(), payloadSize, MSG_NOSIGNAL)};
        if (sent == (int64_t)payloadSize)
        {
            result = SendRetval::SUCCESS;
        }
    }

    return result;
};

// TODO: Are we sure about this?
// This Unix datagram socket implementation is not able to receive messages.
std::vector<char> unixDatagram::recvMsg()
{
    return {};
};

} // namespace sockiface

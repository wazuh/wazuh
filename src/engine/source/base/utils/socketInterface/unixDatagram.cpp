#include "unixDgram.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace base::utils::socketInterface
{
SendRetval unixDgram::sendMsg(const std::string& msg)
{
    auto result {SendRetval::SOCKET_ERROR};
    auto payloadSize {msg.size()};

    // Validate
    if (!this->isConnected())
    {
        this->socketConnect();
    }

    if (0 >= payloadSize)
    {
        result = SendRetval::SIZE_ZERO;
    }
    else if (this->getMaxMsgSize() < payloadSize)
    {
        result = SendRetval::SIZE_TOO_LONG;
    }
    else
    {
        // Send the message
        const auto sent {send(this->getFD(), msg.data(), payloadSize, MSG_NOSIGNAL)};
        if (sent == payloadSize)
        {
            result = SendRetval::SUCCESS;
        }
    }

    return result;
};
} // namespace base::utils::socketInterface

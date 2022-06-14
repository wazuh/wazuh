#include "unixDgram.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace base::utils::socketInterface
{
sndRetval unixDgram::sendMsg(const std::string& msg)
{
    auto result {sndRetval::SOCKET_ERROR};
    auto payloadSize {msg.size()};

    // Validate
    if (!this->isConnected())
    {
        this->sConnect();
    }

    if (0 >= payloadSize)
    {
        result = sndRetval::SIZE_ZERO;
    }
    else if (this->getMaxMsgSize() < payloadSize)
    {
        result = sndRetval::SIZE_TOO_LONG;
    }
    else
    {
        // Send the message
        const auto sent {send(this->getFD(), msg.data(), payloadSize, MSG_NOSIGNAL)};
        if (sent == payloadSize)
        {
            result = sndRetval::SUCCESS;
        }
    }

    return result;
};
} // namespace base::utils::socketInterface

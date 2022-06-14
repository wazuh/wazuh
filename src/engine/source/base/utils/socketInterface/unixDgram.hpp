#ifndef _SOCKETINTERFACE_UNIX_DGRAM_H
#define _SOCKETINTERFACE_UNIX_DGRAM_H

#include "unixInterface.hpp"

namespace base::utils::socketInterface
{
class unixDgram : public unixInterface
{

public:
    unixDgram(std::string_view path, const int maxMsgSize = 65536)
        : unixInterface(path, Protocol::DATAGRAM, maxMsgSize) {};
    ~unixDgram() = default;

    sndRetval sendMsg(const std::string& msg) override;
};
} // namespace base::utils::socketInterface

#endif // _SOCKETINTERFACE_UNIX_DGRAM_H

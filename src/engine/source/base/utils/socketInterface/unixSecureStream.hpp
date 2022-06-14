#ifndef _SOCKETINTERFACE_UNIX_SECSTREAM_H
#define _SOCKETINTERFACE_UNIX_SECSTREAM_H

#include "unixInterface.hpp"

namespace base::utils::socketInterface
{
class unixSecureStream : public unixInterface
{
private:
    /**
     * @brief Receive a message from a stream socket, full message (MSG_WAITALL)
     *
     * @param sock sock file descriptor.
     * @param buf buffer to store the message.
     * @param size size of the buffer.
     * @return int size of the message on success.
     * @return 0 on socket disconnected or timeout.
     * @return \ref SOCKET_ERROR otherwise (and errno is set).
     *
     * @warning This function blocks until the message is received or the socket is
     * disconnected.
     *
     */
    ssize_t recvWaitAll(void* buf, size_t size) const noexcept;

public:

    unixSecureStream(std::string_view path, const int maxMsgSize = 65536)
        : unixInterface(path, Protocol::STREAM, maxMsgSize) {};

    ~unixSecureStream() = default;

    sndRetval sendMsg(const std::string& msg) override;
    std::vector<char> recvMsg() override;
    std::string recvString(); // override;
};
} // namespace base::utils::socketInterface

#endif // _SOCKETINTERFACE_UNIX_SECSTREAM_H

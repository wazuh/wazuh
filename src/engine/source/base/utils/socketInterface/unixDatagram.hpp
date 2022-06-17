#ifndef _SOCKETINTERFACE_UNIX_DATAGRAM_H
#define _SOCKETINTERFACE_UNIX_DATAGRAM_H

#include "unixInterface.hpp"

namespace base::utils::socketInterface
{

constexpr int DATAGRAM_MAX_MSG_SIZE {65536};

/**
 * @brief This class implements an interface to a UNIX datagram socket.
 *
 * @note This Unix datagram socket implementation is not able to receive messages.
 */
class unixDatagram : public unixInterface
{

public:
    /**
     * @brief Create a unixSecureStream object linked to a UNIX socket located at `path`.
     *
     * Set the socket size to the maximum message size (default=2^16).
     * @param path UNIX domain socket pathname
     * @param maxMsgSize Maximum message size (default=2^16)
     * @throw std::invalid_argument if the path is empty
     */
    unixDatagram(std::string_view path, const uint32_t maxMsgSize = DATAGRAM_MAX_MSG_SIZE)
        : unixInterface(path, Protocol::DATAGRAM, maxMsgSize) {};

    ~unixDatagram() = default; // Close de socket in the base class

    /**
     * @brief Send a message to the socket. Open the socket if it is not already open.
     *
     * @param msg message to send.
     *
     * @return SendRetval::SUCCESS on success.
     * @return SendRetval::size_zero if msg is empty.
     * @return SendRetval::size_too_long if msg is too long.
     * @return SendRetval::SOCKET_ERROR if the socket cannot be written to. (errno is
     * set).
     *
     * @throws std::runtime_error if not connected and the socket cannot be connected.
     *
     */
    SendRetval sendMsg(const std::string& msg) override;

    std::vector<char> recvMsg(void) override;
};
} // namespace base::utils::socketInterface

#endif // _SOCKETINTERFACE_UNIX_DGRAM_H

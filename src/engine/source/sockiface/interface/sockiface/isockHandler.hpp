#ifndef _SOCKIFACE_ISOCKHANDLER_HPP
#define _SOCKIFACE_ISOCKHANDLER_HPP

#include <stdexcept>
#include <string>
#include <vector>

namespace sockiface
{
class ISockHandler
{
public:
    /**
     * @brief Specifies the protocol used by the socket.
     */
    enum class Protocol
    {
        STREAM,
        DATAGRAM,
    };

    /**
     * @brief Send operation result codes.
     */
    enum class SendRetval
    {
        SUCCESS,
        SIZE_ZERO,
        SIZE_TOO_LONG,
        SOCKET_ERROR,
    };

    /**
     * @brief Exeption thrown when the socket is not connected but a reconnection is possible.
     *
     * E.g: The socket is closed remotely, the socket is full, broken pipe, connection reset,
     * etc.
     */
    class RecoverableError : public std::runtime_error
    {
    public:
        explicit RecoverableError(const std::string& msg)
            : std::runtime_error(msg)
        {
        }
    };

    virtual ~ISockHandler() = default;

    /**
     * @brief Get the Maximum message size.
     *
     * @return maximum message size.
     */
    virtual uint32_t getMaxMsgSize() const noexcept = 0;

    /**
     * @brief Get the Path to the socket.
     *
     * @return path to the socket.
     */
    virtual std::string getPath() const noexcept = 0;

    /**
     * @brief Connect to the socket, reconnect if already connected.
     *
     * @throws std::runtime_error if the connection fails.
     */
    virtual void socketConnect() = 0;

    /**
     * @brief Disconnect from the socket, if connected.
     */
    virtual void socketDisconnect() = 0;

    /**
     * @brief Check if the socket is connected.
     *
     * @return true if the socket is connected, false otherwise.
     */
    virtual bool isConnected() const noexcept = 0;

    /**
     * @brief Send a message to the socket. Open the socket if it is not already open.
     *
     * @param msg message to send.
     *
     * @return SendRetval::SUCCESS on success.
     * @return SendRetval::SIZE_ZERO if msg is empty.
     * @return SendRetval::SIZE_TOO_LONG if msg is too long.
     * @return SendRetval::SOCKET_ERROR if the socket cannot be written to. (errno is
     * set).
     *
     * @throws std::runtime_error if not connected and the socket cannot be connected.
     * @throws recoverableError if a broken pipe error occurs (EPIPE). Log the
     * warning and disconnect the socket.
     */
    virtual SendRetval sendMsg(const std::string& msg) = 0;

    /**
     * @brief  Receive a message from the socket.
     *
     * @return vector of bytes (char) received terminated by an '\0' character.
     *
     * @throws recoverableError if connection is reset by peer (ECONNRESET), timeout
     * or disconnected (errno is not set).
     * @note This method does not try to connect if the socket is not connected.
     * @warning this method blocks until the message is received or the socket is
     * disconnected.
     */
    virtual std::vector<char> recvMsg() = 0;

    /**
     * @brief Receive a message from the socket and store it in a string.
     *
     * This method is a wrapper around \ref recvMsg.
     * @return string containing the message received.
     * @note This method no try connect if the socket is not connected.
     * @warning this method blocks until the message is received or the socket is
     * disconnected.
     */
    std::string recvString()
    {
        return std::string(recvMsg().data());
    }
};

} // namespace sockiface

#endif // _SOCKIFACE_ISOCKHANDLER_HPP

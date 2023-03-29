#ifndef _SERVER_UNIX_DATAGRAM_HPP
#define _SERVER_UNIX_DATAGRAM_HPP

#include <functional>
#include <memory>

#include "endpoint.hpp"

namespace engineserver::endpoint
{
class UnixDatagram : public Endpoint
{
private:
    std::function<void(std::string&&)> m_callback; ///< Callback function to be called when a message is received
    std::shared_ptr<uvw::UDPHandle> m_handle;      ///< Handle to the socket
    int m_bufferSize;                              ///< Size of the receive buffer

public:
    /**
     * @brief Construct a new Unix Datagram object
     *
     * @param address Path to the socket
     * @param callback Callback function to be called when a message is received
     */
    UnixDatagram(const std::string& address, std::function<void(std::string&&)> callback);

    /**
     * @brief Construct a new Unix Datagram object
     *
     * @param address Path to the socket
     * @param callback Callback function to be called when a message is received, it must return a string to be sent back to the client
     * #TODO: Not implemented yet
     */
    UnixDatagram(const std::string& address, std::function<std::string(std::string&&)> callback);
    ~UnixDatagram();

    /**
     * @copydoc link-object::Endpoint::bind
     */
    void bind(std::shared_ptr<uvw::Loop> loop, const  std::size_t queueWorkerSize = 0) override;

    /**
     * @copydoc link-object::Endpoint::close
     */
    void close(void) override;

    /**
     * @copydoc link-object::Endpoint::pause
     */
    bool pause(void) override;

    /**
     * @copydoc link-object::Endpoint::resume
     */
    bool resume(void) override;

    /**
     * @brief Get the size of the receive buffer
     * @return int Size of the receive buffer
     */
    int getReciveBufferSize(void) { return m_bufferSize; };

};
} // namespace engineserver::endpoint
#endif // _SERVER_UNIX_DATAGRAM_HPP

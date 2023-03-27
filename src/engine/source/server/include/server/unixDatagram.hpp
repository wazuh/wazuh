#ifndef _SERVER_UNIX_DATAGRAM_HPP
#define _SERVER_UNIX_DATAGRAM_HPP

#include <functional>
#include <atomic>

#include "endpoint.hpp"

namespace engineserver::endpoint
{
class UnixDatagram : public Endpoint
{
private:
    std::function<void(std::string&&)> m_callback; // No thread safe
    std::shared_ptr<uvw::UDPHandle> m_handle;
    int m_bufferSize;
    std::atomic<std::size_t> m_currentQWSize;

public:
    UnixDatagram(const std::string& address, std::function<void(std::string&&)> callback);
    UnixDatagram(const std::string& address, std::function<std::string(std::string&&)> callback);
    ~UnixDatagram();

    int getReciveBufferSize(void) { return m_bufferSize; };

    void bind(std::shared_ptr<uvw::Loop> loop, const  std::size_t queueWorkerSize = 0) override;
    void close(void) override;
    bool pause(void) override;
    bool resume(void) override;

};
} // namespace engineserver::endpoint
#endif // _SERVER_UNIX_DATAGRAM_HPP

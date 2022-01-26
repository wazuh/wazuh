#ifndef _TCP_ENDPOINT_H
#define _TCP_ENDPOINT_H

#include "endpoint.hpp"
#include <uvw/tcp.hpp>

#include <functional>
#include <string>
namespace server::endpoints
{

class TcpEndpoint : public Endpoint
{
private:
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::TCPHandle> m_handle;
    std::string m_ip;
    int m_port;

public:
    explicit TcpEndpoint(const std::string & config);
    ~TcpEndpoint();

    void run(void) override;
    void close(void) override;
};
} // namespace server::endpoints

#endif // _TCP_ENDPOINT_H

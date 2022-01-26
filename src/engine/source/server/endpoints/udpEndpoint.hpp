#ifndef _UDP_ENDPOINT_H
#define _UDP_ENDPOINT_H

#include "endpoint.hpp"
#include <uvw/udp.hpp>

#include <functional>
#include <string>
namespace server::endpoints
{

class UdpEndpoint : public Endpoint
{
private:
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::UDPHandle> m_handle;
    std::string m_ip;
    int m_port;

public:
    explicit UdpEndpoint(const std::string & config);
    ~UdpEndpoint();

    void run(void) override;
    void close(void) override;
};
} // namespace server::endpoints

#endif // _UDP_ENDPOINT_H

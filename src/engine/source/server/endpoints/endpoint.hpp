#ifndef _ENDPOINT_H
#define _ENDPOINT_H

#include <functional>
#include <memory>
#include <string>

namespace server::endpoints
{
enum EndpointType
{
    TCP,
    UDP,
    SOCKET
};

class Endpoint
{
protected:
    std::function<void(const std::string &)> m_forward;
};

EndpointType stringToEndpoint(const std::string & endpointName)
{
    if (endpointName == "tcp")
    {
        return TCP;
    }
    else if (endpointName == "udp")
    {
        return UDP;
    }
    else if (endpointName == "socket")
    {
        return SOCKET;
    }
    else
    {
        throw std::invalid_argument("Error, endpoint " + endpointName + " not supported");
    }
}

std::unique_ptr<Endpoint> create(const std::string & type, const std::string & config, std::function<void(const std::string &)> forward)
{
}

} // namespace server::endpoints
#endif // _ENDPOINT_H

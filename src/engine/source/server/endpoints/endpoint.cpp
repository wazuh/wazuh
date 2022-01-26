#include "endpoint.hpp"

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include "tcp_endpoint.hpp"

using namespace std;

namespace server::endpoints
{

Endpoint::Endpoint(function<void(const string &)> forward) : m_forward{forward}
{
}

EndpointType stringToEndpoint(const string & endpointName)
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
        throw invalid_argument("Error, endpoint " + endpointName + " not supported");
    }
}

std::unique_ptr<Endpoint> create(const std::string & type, const std::string & config,
                                 std::function<void(const std::string &)> forward)
{
}
} // namespace server::endpoints

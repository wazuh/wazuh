#include "endpoint.hpp"

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include "tcp_endpoint.hpp"
#include "udp_endpoint.hpp"
#include "socket_endpoint.hpp"

using namespace std;
using namespace rxcpp;

namespace server::endpoints
{

Endpoint::Endpoint(const string & path) : m_path{path}, m_subscriber{m_subject.get_subscriber()}
{
}

observable<nlohmann::json> Endpoint::output(void) const
{
    return this->m_subject.get_observable();
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

std::unique_ptr<Endpoint> create(const std::string & type, const std::string & config)
{
    auto endpointType = stringToEndpoint(type);
    switch (endpointType)
    {
        case TCP:
            return std::make_unique<TcpEndpoint>(config);
            break;
        case UDP:
            return std::make_unique<UdpEndpoint>(config);
            break;
        case SOCKET:
            return std::make_unique<SocketEndpoint>(config);
            break;
        default:
            throw std::runtime_error("Error, endpoint type " + std::to_string(endpointType) +
                                     " not implemented by factory Endpoint builder");
            break;
    }
}
} // namespace server::endpoints

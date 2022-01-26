#ifndef _ENDPOINT_H
#define _ENDPOINT_H

#include <functional>
#include <memory>
#include <string>

namespace server::endpoints
{

class Endpoint
{
protected:
    std::function<void(const std::string &)> m_forward;
    explicit Endpoint(std::function<void(const std::string &)> forward);
};

enum EndpointType
{
    TCP,
    UDP,
    SOCKET
};

EndpointType stringToEndpoint(const std::string & endpointName);

std::unique_ptr<Endpoint> create(const std::string & type, const std::string & config,
                                 std::function<void(const std::string &)> forward);

} // namespace server::endpoints
#endif // _ENDPOINT_H

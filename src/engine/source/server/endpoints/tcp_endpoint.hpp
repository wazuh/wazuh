#ifndef _TCP_ENDPOINT_H
#define _TCP_ENDPOINT_H

#include "endpoint.hpp"

#include <functional>
#include <string>

namespace server::endpoints
{

class TcpEndpoint : public Endpoint
{
public:
    explicit TcpEndpoint(std::function<void(const std::string &)> forward, const std::string& ip, const int& port);
};
} // namespace server::endpoints

#endif // _TCP_ENDPOINT_H

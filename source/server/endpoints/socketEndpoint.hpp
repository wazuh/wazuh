#ifndef _SOCKET_ENDPOINT_H
#define _SOCKET_ENDPOINT_H

#include "endpoint.hpp"
#include <uvw/pipe.hpp>

#include <functional>
#include <string>

namespace server::endpoints
{

class SocketEndpoint : public Endpoint
{
private:
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::PipeHandle> m_handle;
    std::string m_path;

public:
    explicit SocketEndpoint(const std::string & config);
    ~SocketEndpoint();

    void run(void) override;
    void close(void) override;
};
} // namespace server::endpoints

#endif // _SOCKET_ENDPOINT_H

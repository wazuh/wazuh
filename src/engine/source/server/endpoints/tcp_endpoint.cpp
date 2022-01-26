#include "tcp_endpoint.hpp"

#include <functional>
#include <string>
#include <uvw/tcp.hpp>

using namespace std;

namespace server::endpoints
{
TcpEndpoint::TcpEndpoint(std::function<void(const std::string &)> forward, const std::string& ip, const int& port) : Endpoint{forward}
{
    auto loop = uvw::Loop::getDefault();
    auto tcp = loop->resource<uvw::TCPHandle>();

    tcp->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::TCPHandle & tcp)
        {
            std::cerr << "TCP Server (" << tcp.sock().ip.c_str() << ":" << tcp.sock().port
                      << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                      << std::endl;
        });

    tcp->on<uvw::ListenEvent>(
        [this](const uvw::ListenEvent &, uvw::TCPHandle & srv)
        {
            auto client = srv.loop().resource<uvw::TCPHandle>();

            client->on<uvw::ErrorEvent>(
                [](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
                {
                    std::cerr << "TCP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                              << ") error: code=" << event.code() << "; name=" << event.name()
                              << "; message=" << event.what() << std::endl;
                });

            client->on<uvw::DataEvent>(
                [this, &srv](const uvw::DataEvent & event, uvw::TCPHandle & client)
                {
                    auto obs = this->getEndpointSubscriber(EndpointType::TCP, client.sock().port, srv.sock().ip);
                    if (obs)
                    {
                        auto eventObject = parseEvent(std::string(event.data.get(), event.length));
                        if (!eventObject.contains("error"))
                        {
                            obs.value().on_next(eventObject);
                        }
                        else
                        {
                            // TODO: complete this case
                        }
                    }
                    else
                    {
                        std::cerr << "Endpoint could not be found: " << client.sock().port << ":" << srv.sock().ip
                                  << std::endl;
                    }
                });

            client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle & client) { client.close(); });

            srv.accept(*client);
            client->read();
        });

    tcp->bind(ip, port);
    tcp->listen();
}
} // namespace server::endpoints

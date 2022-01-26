#include "udp_endpoint.hpp"

#include "protocol_handler.hpp"
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <uvw/udp.hpp>

using namespace std;

namespace server::endpoints
{
UdpEndpoint::UdpEndpoint(const std::string & config)
    : Endpoint{config}, m_loop{uvw::Loop::getDefault()}, m_handle{m_loop->resource<uvw::UDPHandle>()}
{
    auto pos = config.find(":");
    auto tmp = config.substr(pos + 1);
    pos = tmp.find(":");
    this->m_ip = tmp.substr(0, pos);
    this->m_port = stoi(tmp.substr(pos + 1));

    this->m_handle->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::UDPHandle & udp)
        {
            std::cerr << "UDP Server (" << udp.sock().ip.c_str() << ":" << udp.sock().port
                      << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                      << std::endl;
        });

    this->m_handle->on<uvw::UDPDataEvent>(
        [this](const uvw::UDPDataEvent & event, uvw::UDPHandle & udp)
        {
            auto client = udp.loop().resource<uvw::UDPHandle>();

            client->on<uvw::ErrorEvent>(
                [](const uvw::ErrorEvent & event, uvw::UDPHandle & client)
                {
                    std::cerr << "UDP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                              << ") error: code=" << event.code() << "; name=" << event.name()
                              << "; message=" << event.what() << std::endl;
                });

            auto eventObject = server::protocolhandler::parseEvent(std::string(event.data.get(), event.length));
            if (!eventObject.contains("error"))
            {
                this->m_subscriber.on_next(eventObject);
            }
            else
            {
                // TODO: complete this case
            }
        });

    this->m_handle->bind(this->m_ip, this->m_port);
    this->m_handle->recv();
}

void UdpEndpoint::run(void)
{
    std::thread t(&uvw::Loop::run, this->m_loop.get());
    t.detach();
}

void UdpEndpoint::close(void)
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

UdpEndpoint::~UdpEndpoint()
{
    this->close();
}
} // namespace server::endpoints

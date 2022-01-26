#include "socket_endpoint.hpp"

#include "protocol_handler.hpp"
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <uvw/pipe.hpp>

using namespace std;

namespace server::endpoints
{
SocketEndpoint::SocketEndpoint(const std::string & config)
    : Endpoint{config}, m_loop{uvw::Loop::getDefault()}, m_handle{m_loop->resource<uvw::PipeHandle>()}
{
    this->m_path = config;

    this->m_handle->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::PipeHandle & socket)
        {
            std::cerr << "FIFO Server (" << socket.sock().c_str() << ") error: code=" << event.code()
                      << "; name=" << event.name() << "; message=" << event.what() << std::endl;
        });

    this->m_handle->on<uvw::ListenEvent>(
        [this](const uvw::ListenEvent &, uvw::PipeHandle & handle)
        {
            auto client = handle.loop().resource<uvw::PipeHandle>();

            client->on<uvw::ErrorEvent>(
                [](const uvw::ErrorEvent & event, uvw::PipeHandle & socket)
                {
                    std::cerr << "FIFO Client (" << socket.peer().c_str() << ") error: code=" << event.code()
                              << "; name=" << event.name() << "; message=" << event.what() << std::endl;
                });

            client->on<uvw::DataEvent>(
                [this](const uvw::DataEvent & event, uvw::PipeHandle & client)
                {
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

            client->on<uvw::CloseEvent>([&handle](const uvw::CloseEvent &, uvw::PipeHandle &) { handle.close(); });

            handle.accept(*client);
            client->read();
        });

    {
        struct stat buffer;
        if (stat(this->m_path.c_str(), &buffer) == 0)
        {
            remove(this->m_path.c_str());
        }
    }

    this->m_handle->bind(this->m_path);
    this->m_handle->listen();
}

void SocketEndpoint::run(void)
{
    std::thread t(&uvw::Loop::run, this->m_loop.get());
    t.detach();
}

void SocketEndpoint::close(void)
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

SocketEndpoint::~SocketEndpoint()
{
    this->close();
}
} // namespace server::endpoints

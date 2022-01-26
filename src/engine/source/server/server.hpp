#ifndef _SERVER_H
#define _SERVER_H

#include <memory>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <vector>

#include "endpoints/endpoint.hpp"
#include "protocol_handler.hpp"

namespace server
{

class Server
{
private:
    std::vector<std::unique_ptr<endpoints::Endpoint>> m_endpoints;
    rxcpp::subjects::subject<nlohmann::json> m_subject;
    rxcpp::observable<nlohmann::json> m_output;

    std::function<void(const std::string &)> generateForward() const
    {
        // Generating new subscriber per endpoint
        auto subscriber = m_subject.get_subscriber();
        return [=](const std::string & message) { subscriber.on_next(message); };
    }

public:
    explicit Server(const std::vector<std::string> & config)
    {
        // <EnpointType>:<config_string>
        for (auto endpointConf : config)
        {
            auto pos = endpointConf.find(":");
            this->m_endpoints.push_back(
                endpoints::create(endpointConf.substr(0, pos), endpointConf.substr(pos + 1), this->generateForward()));
        }

        // Build server output observable to emit json events
        this->m_output(this->m_subject.get_observable().map(protocolhandler::parseEvent));
    }

    rxcpp::observable<nlohmann::json> output() const
    {
        return this->m_output;
    }

    void run();
    void stop();
};
} // namespace server

#endif //_SERVER_H

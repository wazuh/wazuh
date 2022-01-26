#ifndef _SERVER_H
#define _SERVER_H

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include "endpoints/endpoint.hpp"
#include "protocol_handler.hpp"

namespace server
{

class Server
{
private:
    std::map<std::string, std::unique_ptr<endpoints::Endpoint>> m_endpoints;
    rxcpp::observable<nlohmann::json> m_output;

public:
    explicit Server(const std::vector<std::string> & config)
    {
        std::vector<rxcpp::observable<nlohmann::json>> tmpObs;
        // <EnpointType>:<config_string> tcp:localhost:5054 socke:path/to/socket
        for (auto endpointConf : config)
        {
            auto pos = endpointConf.find(":");
            this->m_endpoints[endpointConf] =
                endpoints::create(endpointConf.substr(0, pos), endpointConf.substr(pos + 1));
            tmpObs.push_back(this->m_endpoints[endpointConf]->output());
        }

        // Build server output observable to emit json events
        auto output = tmpObs[0];
        for (auto it = ++tmpObs.begin(); it != tmpObs.end(); ++it){
            output = output.merge(*it);
        }
        this->m_output = output;
    }

    rxcpp::observable<nlohmann::json> output() const
    {
        return this->m_output;
    }

    void run()
    {
        for (auto it = this->m_endpoints.begin(); it != this->m_endpoints.end(); ++it)
        {
            it->second->run();
        }
    }
    void stop(){
        for (auto it = this->m_endpoints.begin(); it != this->m_endpoints.end(); ++it)
        {
            it->second->close();
        }
    }
};
} // namespace server

#endif //_SERVER_H

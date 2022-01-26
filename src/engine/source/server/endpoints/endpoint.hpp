#ifndef _ENDPOINT_H
#define _ENDPOINT_H

#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <string>

namespace server::endpoints
{

class Endpoint
{
protected:
    rxcpp::subjects::subject<nlohmann::json> m_subject;
    rxcpp::subscriber<nlohmann::json> m_subscriber;
    std::string m_path;

    explicit Endpoint(const std::string & path);

public:
    virtual ~Endpoint();
    /**
     * @brief Get the Observable object
     *
     * @return auto Observable object
     */
    rxcpp::observable<nlohmann::json> output(void) const;

    virtual void run(void) = 0;
    virtual void close(void) = 0;
};

enum EndpointType
{
    TCP,
    UDP,
    SOCKET
};

EndpointType stringToEndpoint(const std::string & endpointName);

std::unique_ptr<Endpoint> create(const std::string & type, const std::string & config);

} // namespace server::endpoints
#endif // _ENDPOINT_H

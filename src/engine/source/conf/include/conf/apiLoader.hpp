#ifndef _CONF_APILOADER_HPP
#define _CONF_APILOADER_HPP

#include <base/json.hpp>

namespace conf
{
struct IApiLoader
{
protected:
    /**
     * @brief Load the configuration from the API.
     *
     * @throw std::runtime_error If cannot retrieve the configuration from the framework API.
     * @return json::Json
     */
    virtual json::Json load() const = 0;

public:
    virtual ~IApiLoader() = default;

    /**
     * @brief Load the configuration from the API.
     *
     * @throw std::runtime_error If cannot retrieve the configuration from the framework API.
     * @return json::Json
     */
    json::Json operator()() const { return load(); }
};

class ApiLoader : public IApiLoader
{
public:
    json::Json load() const override;
};

} // namespace conf

#endif // _CONF_APILOADER_HPP

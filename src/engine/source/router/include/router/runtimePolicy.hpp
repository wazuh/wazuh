#ifndef _ROUTER_RUNTIME_ENVIRONMENT_HPP
#define _ROUTER_RUNTIME_ENVIRONMENT_HPP

#include <optional>
#include <string>

#include <builder.hpp>
#include <error.hpp>
#include <rxbk/rxFactory.hpp>

namespace router
{

/**
 * @brief Runtime policy represent an policy in memory, ready to be builed and
 * run
 * @note This class is not thread safe
 */
class RuntimePolicy
{
private:
    std::string m_asset;
    std::shared_ptr<rxbk::Controller> m_controller;

public:
    /**
     * @brief Construct a new Runtime Policy object
     *
     * @param asset Asset of the policy
     */
    RuntimePolicy(std::string asset)
        : m_asset {asset}
        , m_controller {}
    {
    }

    ~RuntimePolicy() = default;

    /**
     * @brief Build the policy and instantiate the controller.
     *
     * @param builder Builder to be used for policy creation
     * @return Error message if creation fails
     *
     * @note: This function is not thread safe. Only one policy can be built at a time.
     */
    std::optional<base::Error> build(std::shared_ptr<builder::Builder> builder);

    /**
     * @brief Inyect an event into the policy
     *
     * @param event Event to be inyect
     * @return std::optional<base::Error>
     *
     * @note This function is not thread safe. Only one event at a time, because the expression tree (helper
     * functions) are not thread safe.
     */
    std::optional<base::Error> processEvent(base::Event event);
};

} // namespace router

#endif // _ROUTER_RUNTIME_ENVIRONMENT_HPP

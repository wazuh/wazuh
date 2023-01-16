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
 * @brief Runtime environment represent an environment in memory, ready to be builed and
 * run
 *
 * TODO: Should be a thread safe class? (I think not).
 *  Mutex not only protect the environment, but also the pipeline. 1 event por pipeline at a time.
 */
class RuntimeEnvironment
{
private:
    std::string m_asset;
    std::shared_ptr<rxbk::Controller> m_controller;

public:
    /**
     * @brief Construct a new Runtime Environment object
     *
     * @param asset Asset of the environment
     */
    RuntimeEnvironment(std::string asset)
        : m_asset {asset}
        , m_controller {}
    {
    }

    ~RuntimeEnvironment() = default;

    /**
     * @brief Build the environment and instantiate the controller.
     *
     * @param builder Builder to be used for environment creation
     * @return Error message if creation fails
     *
     * @note: This function is not thread safe. Only one environment can be built at a time.
     */
    std::optional<base::Error> build(std::shared_ptr<builder::Builder> builder);

    /**
     * @brief Inyect an event into the environment
     *
     * @param event Event to be inyect
     * @return std::optional<base::Error>
     *
     * @note This function is not thread safe. Only one event at a time, because the expression tree (helper
     * functions) are not thread safe.
     */
    std::optional<base::Error> pushEvent(base::Event event);
};

} // namespace router

#endif // _ROUTER_RUNTIME_ENVIRONMENT_HPP

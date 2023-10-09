#ifndef _ROUTER_RUNTIME_ENVIRONMENT_HPP
#define _ROUTER_RUNTIME_ENVIRONMENT_HPP

#include <optional>
#include <string>

#include <builder.hpp>
#include <error.hpp>
#include <bk/icontroller.hpp>

namespace router
{

using OutputSubscriber = std::function<void(base::Event&&)>;

/**
 * @brief Runtime policy represent an policy in memory, ready to be builed and
 * run
 * @note This class is not thread safe
 */
class RuntimePolicy
{
private:
    std::string m_asset;
    std::string m_hash;
    std::shared_ptr<bk::IController> m_controller;

    struct TraceSubscription {
        OutputSubscriber publishOutput;                    ///< output callback
        std::vector<std::pair< std::string, bk::Subscription>>  subscriptions {}; /// < subscriptions to the trace events
    } m_trace;



public:
    /**
     * @brief Construct a new Runtime Policy object
     *
     * @param asset Asset of the policy
     */
    RuntimePolicy(std::string asset)
        : m_asset {asset}
        , m_controller {}
        , m_hash {}
        , m_trace {}
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
    std::optional<base::Error> processEvent(base::Event&& event);

    /**
     * @brief Complete the policy, needed to be able to free rxcpp resources
     *
     */
    void complete()
    {
        if (m_controller)
        {
            m_controller->stop();
        }
    }

    /**
     * @brief Subscribes to output events and receives generated output data.
     *
     * This function subscribes to output events and receives the generated output data via the provided callback
     * function. Whenever an output event occurs, the callback function specified by `callback` will be invoked with the
     * corresponding output data.
     *
     * @param callback The callback function to be invoked with the generated output data.
     * @return std::optional<base::Error> If the subscription encounters an error, an error message is returned.
     *         Otherwise, returns std::nullopt if the subscription was successful.
     */
    std::optional<base::Error> subscribeToOutput(const OutputSubscriber& callback);

    /**
     * @brief Listens to all trace events and receives generated trace data.
     *
     * This function listens to all trace events and receives the generated trace data via the provided callback
     * function. Whenever a trace event occurs, the callback function specified by `callback` will be invoked with the
     * corresponding trace data.
     *
     * @param callback The callback function to be invoked with the generated trace data.
     * @param assets Vector of asset names to subscribe to.
     * @return std::optional<base::Error> If the listening encounters an error, an error message is returned.
     *         Otherwise, returns std::nullopt if the listening was successful.
     */
    std::optional<base::Error> listenAllTrace(const bk::Subscriber& callback,
                                              const std::vector<std::string>& assets);

    /**
     * @brief Get the Assets object
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> getAssets() const;

    /**
     * @brief
     *
     */
    void unSubscribeTraces();

    /**
     * @brief Get the hash of the policy
     *
     * @return const std::string&
     */
    const std::string& hash() const
    {
        return m_hash;
    }
};

} // namespace router

#endif // _ROUTER_RUNTIME_ENVIRONMENT_HPP

#ifndef _ROUTER_POLICY_MANAGER_HPP
#define _ROUTER_POLICY_MANAGER_HPP

#include <router/runtimePolicy.hpp>

#include <map>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include <error.hpp>

namespace router
{

/**
 * @brief PolicyManager is responsible to manage the runtime policy,
 * Creacion, destruction, and interaction with the policy.
 * The policy manager create multiples instaces of the same policies this
 * allow interact to the same policy from different threads without any synchronization.
 */
class PolicyManager
{

private:
    /* Status */
    std::unordered_map<std::string, std::vector<RuntimePolicy>> m_policies; ///< Map of policies
    std::shared_mutex m_mutex;                                              ///< Mutex to protect the policies map

    /* Config */
    const std::size_t m_numInstances; ///< Number of instances of each policy

    /* Resources */
    std::shared_ptr<builder::Builder> m_builder; ///< Builder for policy creation

public:
    /**
     * @brief Create the policy manager
     *
     * The policy manager is responsible to manage the runtime policy, creation, destruction, and interaction
     * with the policy
     * @param builder Builder for policy creation
     * @param maxInstances Number of instances of each policy
     */
    PolicyManager(std::shared_ptr<builder::Builder> builder, std::size_t maxInstances)
        : m_policies {}
        , m_mutex {}
        , m_numInstances {maxInstances}
        , m_builder {builder}
    {
        if (0 == maxInstances)
        {
            throw std::runtime_error("PolicyManager: Number of instances of the policy cannot be 0");
        }

        if (nullptr == builder)
        {
            throw std::runtime_error("PolicyManager: Builder cannot be null");
        }
    };

    ~PolicyManager() { delAllPolicies(); };

    /**
     * @brief Create a new policy
     *
     * @param name Name of the policy
     * @return Error message if any
     */
    std::optional<base::Error> addPolicy(const std::string& name);

    /**
     * @brief Delete an policy
     *
     * @param name Name of the policy
     * @return Error message if any
     */
    std::optional<base::Error> deletePolicy(const std::string& name);

    /**
     * @brief Delete all policies
     */
    void delAllPolicies();

    /**
     * @brief Get a list of all policies
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> listPolicies();

    /**
     * @brief Forward an event to an policy
     *
     * @param name Name of the policy
     * @param instance Instance of the policy
     * @param event Event to forward
     * @return std::optional<base::Error> if the event can't be forwarded
     *
     * @note The instance of the policy should be selected by the thread id,
     * the instance of an policy is not thread safe for processing events.
     * The lamda function of the expression is not thread safe.
     */
    std::optional<base::Error> forwardEvent(const std::string& name, std::size_t instance, base::Event&& event);

    /**
     * @brief Subscribes to a callback that generates the outputs and traces corresponding to each event.
     *
     * This function subscribes to a callback mechanism that generates the outputs and traces corresponding
     * to each event for a specified policy and its instance. The generated output and trace data will be
     * passed to the provided `outputCallback` and `traceCallback` functions.
     *
     * @param outputCallback The callback function to be invoked with the generated output data.
     * @param traceCallback The callback function to be invoked with the generated trace data.
     * @param assets Vector of asset names to subscribe to.
     * @param name Name of the policy for which output and trace are to be obtained.
     * @param instance Instance of the policy for which output and trace are to be obtained.
     * @return std::optional<base::Error> If the policy is not configured for test mode, an error is returned.
     *         Otherwise, returns std::nullopt if the subscription was successful.
     */
    std::optional<base::Error> subscribeOutputAndTraces(const OutputSubscriber& outputCallback,
                                                        const bk::Subscriber& traceCallback,
                                                        const std::vector<std::string>& assets,
                                                        const std::string& name);

    /**
     * @brief Get the Assets object
     *
     * @param name
     * @param instance
     * @return base::RespOrError<std::vector<std::string>>
     */
    base::RespOrError<std::vector<std::string>> getAssets(const std::string& name, std::size_t instance = 0);

    /**
     * @brief
     *
     * @param name
     * @param instance
     * @return base::OptError
     */
    base::OptError unSubscribeTraces(const std::string& name, std::size_t instance);

    /**
     * @brief Get the hash of the policy
     *
     * @return std::optional<std::string> Hash of the policy, or std::nullopt if the policy does not loaded
     */
    std::optional<std::string> getPolicyHash(const std::string& name);

};
} // namespace router

#endif // _ROUTER_POLICY_MANAGER_HPP

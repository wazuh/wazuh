#ifndef _BK_ICONTROLLER_HPP
#define _BK_ICONTROLLER_HPP

#include <functional>
#include <memory>
#include <string_view>
#include <unordered_set>

#include <base/baseTypes.hpp>
#include <base/error.hpp>
#include <base/expression.hpp>

namespace bk
{

using Subscriber = std::function<void(const std::string&, bool)>; ///< Suscriber type for traces and result
using Subscription = std::size_t;                                 ///< Identifier of the subscription.

/**
 * @brief Interface for the backend.
 *
 * @tparam Event The type of the data that is ingested.
 */
class IController
{
public:
    virtual ~IController() = default;

    /**
     * @brief Ingest the data into the backend.
     *
     * @param data The data to ingest.
     * @note this method is not thread-safe and its blocking.
     * @throw std::runtime_error if cannot ingest the data (e.g. the backend is not started, not thread-safe, etc.)
     */
    virtual void ingest(base::Event&& event) = 0;

    /**
     * @brief Ingest the data into the backend and get the result of processing the data.
     *
     * @param event The data to ingest.
     * @return base::Event The result of processing the data.
     * @note this method is not thread-safe and its blocking.
     * @throw std::runtime_error if cannot ingest the data (e.g. the backend is not started, not thread-safe, etc.)
     */
    virtual base::Event ingestGet(base::Event&& event) = 0;

    /**
     * @brief Check if the backend is available to ingest data. i.e. if the backend is started and built correctly.
     *
     * @return true if the backend is available to ingest data. false otherwise.
     */
    virtual bool isAviable() const = 0;

    /**
     * @brief Start the backend.
     *
     */
    virtual void start() = 0;

    /**
     * @brief Close the backend and free the resources.
     *
     * After calling this method, the backend is not usable anymore.
     */
    virtual void stop() = 0;

    /**
     * @brief Get the graph of execution of the backend as a string.
     *
     * Get the graph of execution of the backend as a string. The graph is in the DOT format.
     * The graph is the representation of the execution of the backend, each backend has its own graph.
     * @return std::string
     */
    virtual std::string printGraph() const = 0;

    /**
     * @brief Get the traceables that are available in the backend.
     *
     * @return const std::unordered_set<std::string>& The traceables that are available in the backend.
     */
    virtual const std::unordered_set<std::string>& getTraceables() const = 0;

    /**
     * @brief Subscribe a subscriber to a traceable.
     *
     * @param traceable the traceable to subscribe to.
     * @param subscriber the subscriber function to subscribe.
     * @return base::RespOrError<ITrace::Subscription>
     */
    virtual base::RespOrError<Subscription> subscribe(const std::string& traceable, const Subscriber& subscriber) = 0;

    /**
     * @brief Unsubscribe a subscriber from a traceable.
     *
     * @param traceable the traceable to unsubscribe from.
     * @param subscription the subscription identifier to unsubscribe.
     */
    virtual void unsubscribe(const std::string& traceable, Subscription subscription) = 0;

    /**
     * @brief Clean all the subscribers from all the traceables.
     *
     */
    virtual void unsubscribeAll() = 0;
};

/**
 * @brief Interface for the backend factory.
 *
 * @tparam IController The type of the backend.
 */
class IControllerMaker
{
public:
    virtual ~IControllerMaker() = default;

    /**
     * @brief Create a new controller.
     *
     * @return std::shared_ptr<IController>
     */
    virtual std::shared_ptr<IController> create(const base::Expression& expression,
                                                const std::unordered_set<std::string>& traceables,
                                                const std::function<void()>& endCallback) = 0;

    std::shared_ptr<IController> create(const base::Expression& expression,
                                        const std::unordered_set<std::string>& traceables)
    {
        return create(expression, traceables, nullptr);
    }
};

} // namespace bk

#endif // _BK_ICONTROLLER_HPP

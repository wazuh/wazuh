#ifndef BK_ICONTROLLER_HPP
#define BK_ICONTROLLER_HPP

#include <functional>
#include <memory>
#include <string_view>

#include <baseTypes.hpp>
#include <error.hpp>
#include <expression.hpp>

namespace bk
{
/**
 * @brief Interface for the trace
 *
 * The trace is the way to get the data from each traceable expression when it is evaluated in the backend.
 */
class ITrace
{
public:
    using Subscriber = std::function<void(std::string_view)>; ///< Suscriber type.
    using Subscription = std::size_t;                         ///< Identifier of the subscription.
    using Publisher = std::function<void(std::string_view)>;  ///< Used to publish the trace to the subscribers.
    virtual ~ITrace() = default;

    /**
     * @brief Get the name of the trace.
     *
     * @return const std::string& The name of the trace.
     */
    virtual const std::string& name() const = 0;

    /**
     * @brief Subscribe `subscriber` to the trace.
     *
     * @param subscriber The subscriber to subscribe.
     * @return base::RespOrError<Subscription> The subscription identifier or error if the subscription failed.
     */
    virtual base::RespOrError<Subscription> subscribe(const Subscriber& subscriber) = 0;

    /**
     * @brief Unsubscribe a subscriber from the trace.
     *
     * @param subscription The subscription identifier to unsubscribe.
     */
    virtual void unsubscribe(Subscription subscription) = 0;

    /**
     * @brief Get the publisher of the trace.
     *
     * @return Publisher
     */
    virtual Publisher publisher() = 0;
};

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
     * @brief Use the backend as a filter, evaluating the expression with the event and returning the last result of the
     * evaluated term
     *
     * @param event
     * @return true
     * @return false
     * @throw std::runtime_error if cannot ingest the data (e.g. the backend is not started, not thread-safe, etc.)
     */
    // virtual bool filter(const base::Event& event) = 0;

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
    virtual base::RespOrError<ITrace::Subscription> subscribe(const std::string& traceable,
                                                              const ITrace::Subscriber& subscriber) = 0;

    /**
     * @brief Unsubscribe a subscriber from a traceable.
     *
     * @param traceable the traceable to unsubscribe from.
     * @param subscription the subscription identifier to unsubscribe.
     */
    virtual void unsubscribe(const std::string& traceable, ITrace::Subscription subscription) = 0;
};

} // namespace bk

#endif // BK_ICONTROLLER_HPP
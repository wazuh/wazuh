#ifndef BK_ICONTROLLER_HPP
#define BK_ICONTROLLER_HPP

#include <functional>
#include <memory>
#include <string_view>

#include <error.hpp>
#include <expression.hpp>
#include <baseTypes.hpp>

namespace bk
{

class ITrace
{
public:
    using Subscriber = std::function<void(std::string_view)>;
    using Subscription = std::size_t;
    using Publisher = std::function<void(std::string_view)>;

    virtual ~ITrace() = default;

    virtual const std::string& name() const = 0;
    virtual base::RespOrError<Subscription> subscribe(const Subscriber& subscriber) = 0;
    virtual void unsubscribe(Subscription subscription) = 0;
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
     *
     * @throw std::runtime_error If the backend is not built.
     * TODO: blocking or non-blocking?, should return a future, status, IEvent or something else?
     * TODO: should be thread safe?
     */
    virtual void ingest(base::Event&& event) = 0;

    virtual base::Event ingestGet(base::Event&& event) = 0;

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

    virtual const std::unordered_set<std::string>& getTraceables() const = 0;
    virtual base::RespOrError<ITrace::Subscription> subscribe(const std::string& traceable, const ITrace::Subscriber& subscriber) = 0;
    virtual void unsubscribe(const std::string& traceable, ITrace::Subscription subscription) = 0;
};

} // namespace bk

#endif // BK_ICONTROLLER_HPP

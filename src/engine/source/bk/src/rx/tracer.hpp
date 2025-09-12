#ifndef _BK_RX_TRACER_HPP
#define _BK_RX_TRACER_HPP

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <base/error.hpp>
#include <bk/icontroller.hpp>

namespace bk::rx::detail
{
using Publisher = Subscriber;

class Tracer : public std::enable_shared_from_this<Tracer>
{
private:
    std::string m_name;                                         ///< Name of the trace
    std::unordered_map<Subscription, Subscriber> m_subscribers; ///< subscription id -> subscriber map

    Subscription m_nextSubId {0};                      ///< Next subscription id
    Subscription nextSubId() { return m_nextSubId++; } ///< Get the next subscription id

    std::shared_mutex m_subscribersMutex; ///< Mutex for the subscribers

public:
    virtual ~Tracer() = default;

    /**
     * @brief Get the name of the trace.
     *
     * @return const std::string& The name of the trace.
     */
    inline const std::string& name() const { return m_name; }

    /**
     * @brief Subscribe `subscriber` to the trace.
     *
     * @param subscriber The subscriber to subscribe.
     * @return base::RespOrError<Subscription> The subscription identifier or error if the subscription failed.
     */
    inline base::RespOrError<Subscription> subscribe(const Subscriber& subscriber)
    {
        std::unique_lock lock {m_subscribersMutex};
        auto id = nextSubId();
        if (m_subscribers.find(id) != m_subscribers.end())
        {
            return base::Error {"Subscription already exists"};
        }

        m_subscribers.emplace(id, subscriber);
        return id;
    }

    /**
     * @brief Unsubscribe a subscriber from the trace.
     *
     * @param subscription The subscription identifier to unsubscribe.
     */
    inline void unsubscribe(Subscription subscription)
    {
        std::unique_lock lock {m_subscribersMutex};
        m_subscribers.erase(subscription);
    }

    /**
     * @copydoc bk::ITrace::publisher
     */
    Publisher publisher()
    {
        return [thisPtr = this->weak_from_this()](const std::string& message, bool success)
        {
            auto thisShared = thisPtr.lock();
            std::shared_lock lock {thisShared->m_subscribersMutex};
            for (const auto& [_, subscriber] : thisShared->m_subscribers)
            {
                subscriber(message, success);
            }
        };
    }

    /**
     * @brief Clean all the subscribers from the trace.
     *
     */
    void unsubscribeAll()
    {
        std::unique_lock lock {m_subscribersMutex};
        m_subscribers.clear();
    }
};

} // namespace bk::rx::detail

#endif // _BK_RX_TRACER_HPP

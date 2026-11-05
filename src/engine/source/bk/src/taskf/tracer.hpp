// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BK_TASKF_TRACER_HPP
#define _BK_TASKF_TRACER_HPP

#include <cassert>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <base/error.hpp>
#include <bk/icontroller.hpp>

namespace bk::taskf::detail
{
using Publisher = Subscriber;

class Tracer : public std::enable_shared_from_this<Tracer>
{
private:
    std::unordered_map<Subscription, Subscriber> m_subscribers; ///< subscription id -> subscriber map

    Subscription m_nextSubId {0};                      ///< Next subscription id
    Subscription nextSubId() { return m_nextSubId++; } ///< Get the next subscription id

    std::shared_mutex m_subscribersMutex; ///< Mutex for the subscribers

public:
    virtual ~Tracer() = default;

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
            // Unreachable while the Tracer lives in the Controller's m_traces map: it is already
            // owned by a shared_ptr when publisher() is called, and the map outlives the executor.
            // Guarded anyway: dereferencing a null lock() would be undefined behaviour, and a future
            // ownership change must fail loudly in Debug instead of silently dropping traces.
            assert(thisShared && "Tracer destroyed before its publisher");
            if (!thisShared)
            {
                return;
            }
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

} // namespace bk::taskf::detail

#endif // _BK_TASKF_TRACER_HPP

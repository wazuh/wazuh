#ifndef _ROUTER_AUX_FUNCTIONS_H
#define _ROUTER_AUX_FUNCTIONS_H

#include <blockingconcurrentqueue.h>

#include "parseEvent.hpp"

#include "utils/stringUtils.hpp"
#include <builder.hpp>
#include <registry.hpp>

namespace aux
{
std::shared_ptr<builder::Builder> getFakeBuilder();

const std::vector<std::string> sampleEventsStr {
    R"(2:10.0.0.1:Test Event - deco_1 )", R"(4:10.0.0.1:Test Event - deco_2 )", R"(8:10.0.0.1:Test Event - deco_3 )"};

base::Event createFakeMessage(std::optional<std::string> msgOpt = std::nullopt);

struct testQueue
{
    std::shared_ptr<moodycamel::BlockingConcurrentQueue<base::Event>> m_eventQueue;

    std::shared_ptr<moodycamel::BlockingConcurrentQueue<base::Event>> getQueue()
    {
        if (m_eventQueue == nullptr)
        {
            m_eventQueue = std::make_shared<moodycamel::BlockingConcurrentQueue<base::Event>>(100);
        }
        return m_eventQueue;
    }

    void pushEvent(const base::Event& event)
    {
        bool res = getQueue()->enqueue(event);
        if (!res)
        {
            throw std::runtime_error("Error pushing event to queue");
        }
    }
};

} // namespace aux

#endif // _ROUTER_AUX_FUNCTIONS_H

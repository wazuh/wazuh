#ifndef _H_EVENT_HANDLER
#define _H_EVENT_HANDLER

#include <json.hpp>

namespace base
{

class EventHandler
{

private:
    // Control
    bool is_decoded;
    // Data
    std::shared_ptr<json::Document> event;

public:
    /**
     * @brief Construct a new Event Handler from event
     *
     * @param event
     */
    EventHandler(std::shared_ptr<json::Document> event)
        : event {event}
        , is_decoded {false}
    {
        // TODO Throw exception if shared_ptr is empty
    }

    /**
     * @brief Get the Event
     *
     * @return std::shared_ptr<json::Document>
     */
    std::shared_ptr<json::Document> getEvent()
    {
        return event;
    }
};



} // namespace Base
#endif

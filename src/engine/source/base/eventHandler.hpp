#ifndef _H_EVENT_HANDLER
#define _H_EVENT_HANDLER

#include <json.hpp>

namespace base
{

class EventHandler
{

private:
    // Control
    bool is_decoded; ///< True if it reached the end of the decoding stage
    // Data
    std::shared_ptr<json::Document> event; ///< Event

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

    /**
     * @brief Checks if the event was decoded
     *
     * @return return true if it reached the end of the decoding stage
     */
    bool isDecoded() {
        return is_decoded;
    }

    /**
     * @brief Changes event status to decoded
     */
    void setDecoded() {
        is_decoded = true;
    }
};



} // namespace Base
#endif

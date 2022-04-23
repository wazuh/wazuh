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
     * @brief Get the Decoded
     *
     * @return bool
     */
    bool getDecoded() {
        return is_decoded;
    }

    /**
     * @brief Set the Decoded
     *
     * @param decoded
     */
    void setDecoded(bool decoded) {
        is_decoded = decoded;
    }
};



} // namespace Base
#endif

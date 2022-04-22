#ifndef _H_EVENT_HANDLER
#define _H_EVENT_HANDLER

#include <json.hpp>

namespace Base
{

class EventHandler
{

private:
    bool is_decoded;
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
     * @brief Get the boolean that indicates if the event is decoded
     *
     * @return bool
     */
    bool getIsDecoded() {
        return is_decoded;
    }

    /**
     * @brief Set the boolean that indicates if the event is decoded
     *
     * @param is_decoded
     */
    void setIsDecoded(bool is_decoded) {
        this->is_decoded = is_decoded;
    }
};

} // namespace Base
#endif

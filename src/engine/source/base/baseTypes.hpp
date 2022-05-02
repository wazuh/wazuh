#ifndef _H_BASE_TYPES
#define _H_BASE_TYPES

#include "eventHandler.hpp"

#include <rxcpp/rx.hpp>


namespace base
{
    using Event = std::shared_ptr<EventHandler>;
    using Document = json::Document;
    using DocumentValue = json::Value;
    using Observable = rxcpp::observable<Event>;
    using Lifter = std::function<Observable(Observable)>;
}

#endif //_H_BASE_TYPES

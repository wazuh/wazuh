#ifndef _H_BASE_TYPES
#define _H_BASE_TYPES

#include <rxcpp/rx.hpp>

#include "eventHandler.hpp"

namespace base
{
    using Event = std::shared_ptr<EventHandler>;
    using Document = json::Document;
    using DocumentValue = json::Value; // TODO Se usa??
    using Observable = rxcpp::observable<Event>;
    using Lifter = std::function<Observable(Observable)>;
}

#endif //_H_BASE_TYPES

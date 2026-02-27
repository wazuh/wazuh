#ifndef _H_BASE_TYPES
#define _H_BASE_TYPES

#include "result.hpp"
#include <base/json.hpp>
#include <functional>

namespace base
{
using Event = std::shared_ptr<json::Json>;         ///< Shared pointer to a mutable JSON event.
using ConstEvent = const std::shared_ptr<const json::Json>&; ///< Reference to a shared pointer to an immutable JSON event.
using EngineOp = std::function<result::Result<Event>(Event)>; ///< Engine operation: receives an Event and returns a Result.
} // namespace base

#endif //_H_BASE_TYPES

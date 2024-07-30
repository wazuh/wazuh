#ifndef _H_BASE_TYPES
#define _H_BASE_TYPES

#include <base/json.hpp>
#include "result.hpp"
#include <functional>

namespace base
{
using Event = std::shared_ptr<json::Json>;
using ConstEvent = const std::shared_ptr<const json::Json>&;
using EngineOp = std::function<result::Result<Event>(Event)>;
} // namespace base

#endif //_H_BASE_TYPES

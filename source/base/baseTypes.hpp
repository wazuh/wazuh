#ifndef _H_BASE_TYPES
#define _H_BASE_TYPES

#include "json.hpp"
#include "result.hpp"

namespace base
{
using Event = std::shared_ptr<json::Json>;
using EngineOp = std::function<result::Result<Event>(Event)>;
} // namespace base

#endif //_H_BASE_TYPES

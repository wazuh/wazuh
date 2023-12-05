#ifndef _BUILDER_BUILDERS_UTILS_HPP
#define _BUILDER_BUILDERS_UTILS_HPP

#include "ibuildCtx.hpp"

#define RETURN_FAILURE(runState, ret, traceMsg)                                                                      \
    if ((runState)->trace)                                                                                             \
    {                                                                                                                  \
        return base::result::makeFailure<decltype(ret)>(ret, traceMsg);                                                             \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeFailure<decltype(ret)>(ret);                                                                       \
    }

#define RETURN_SUCCESS(runState, ret, traceMsg)                                                                      \
    if ((runState)->trace)                                                                                             \
    {                                                                                                                  \
        return base::result::makeSuccess<decltype(ret)>(ret, traceMsg);                                                             \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeSuccess<decltype(ret)>(ret);                                                                       \
    }

namespace builder::builders::utils
{

inline void assertSize(const std::vector<OpArg>& args, size_t size)
{
    if (args.size() != size)
    {
        throw std::runtime_error(fmt::format("Expected {} arguments, got {}", size, args.size()));
    }
}


} // namespace builder::builders::utils

#endif // _BUILDER_BUILDERS_UTILS_HPP

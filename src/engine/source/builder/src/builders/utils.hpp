#ifndef _BUILDER_BUILDERS_UTILS_HPP
#define _BUILDER_BUILDERS_UTILS_HPP

#include "types.hpp"

#define RETURN_FAILURE(runState, ret, traceMsg)                                                                        \
    if ((runState)->trace)                                                                                             \
    {                                                                                                                  \
        return base::result::makeFailure<decltype(ret)>(ret, traceMsg);                                                \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeFailure<decltype(ret)>(ret);                                                          \
    }

#define RETURN_SUCCESS(runState, ret, traceMsg)                                                                        \
    if ((runState)->trace)                                                                                             \
    {                                                                                                                  \
        return base::result::makeSuccess<decltype(ret)>(ret, traceMsg);                                                \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeSuccess<decltype(ret)>(ret);                                                          \
    }

namespace builder::builders::utils
{
auto constexpr MAX_OP_ARGS = 40;

inline void assertSize(const std::vector<OpArg>& args, size_t minSize, size_t maxSize = 0)
{
    if (maxSize == 0)
    {
        if (args.size() != minSize)
        {
            throw std::runtime_error(fmt::format("Expected {} arguments, got {}", minSize, args.size()));
        }
    }
    else if (args.size() < minSize || args.size() > maxSize)
    {
        throw std::runtime_error(
            fmt::format("Expected between {} and {} arguments, got {}", minSize, maxSize, args.size()));
    }
}

template<typename... Idx>
inline void assertRef(const std::vector<OpArg>& args, Idx... idx)
{
    if (sizeof...(idx) == 0)
    {
        for (size_t i = 0; i < args.size(); ++i)
        {
            if (!args[i]->isReference())
            {
                throw std::runtime_error(fmt::format("Expected argument {} to be a reference", i + 1));
            }
        }
    }
    else
    {
        (
            [](const std::vector<OpArg>& args, size_t i)
            {
                if (!args[i]->isReference())
                {
                    throw std::runtime_error(fmt::format("Expected argument {} to be a reference", i + 1));
                }
            }(args, idx),
            ...);
    }
}

template<typename... Idx>
inline void assertValue(const std::vector<OpArg>& args, Idx... idx)
{
    if (sizeof...(idx) == 0)
    {
        for (size_t i = 0; i < args.size(); ++i)
        {
            if (!args[i]->isValue())
            {
                throw std::runtime_error(fmt::format("Expected argument {} to be a value", i + 1));
            }
        }
    }
    else
    {
        (
            [](const std::vector<OpArg>& args, size_t i)
            {
                if (!args[i]->isValue())
                {
                    throw std::runtime_error(fmt::format("Expected argument {} to be a value", i + 1));
                }
            }(args, idx),
            ...);
    }
}

} // namespace builder::builders::utils

#endif // _BUILDER_BUILDERS_UTILS_HPP

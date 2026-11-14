// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef BUILDER_BUILDERS_UTILS_HPP
#define BUILDER_BUILDERS_UTILS_HPP

#include "types.hpp"

/** @brief Return a failure result, optionally including a trace message when test mode is enabled. */
#define RETURN_FAILURE(isTestMode, ret, traceMsg)                                                                      \
    if (isTestMode)                                                                                                    \
    {                                                                                                                  \
        return base::result::makeFailure<decltype(ret)>(ret, traceMsg);                                                \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeFailure<decltype(ret)>(ret);                                                          \
    }

/** @brief Return a success result, optionally including a trace message when test mode is enabled. */
#define RETURN_SUCCESS(isTestMode, ret, traceMsg)                                                                      \
    if (isTestMode)                                                                                                    \
    {                                                                                                                  \
        return base::result::makeSuccess<decltype(ret)>(ret, traceMsg);                                                \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeSuccess<decltype(ret)>(ret);                                                          \
    }

namespace builder::builders::utils
{
auto constexpr MAX_OP_ARGS = 150; ///< Maximum number of operation arguments.

/**
 * @brief Assert that the number of arguments matches the expected range.
 *
 * @param args Arguments vector.
 * @param minSize Minimum number of arguments.
 * @param maxSize Maximum number of arguments (0 means exact match with minSize).
 * @throws std::runtime_error If the argument count is out of range.
 */
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

/**
 * @brief Assert that the specified arguments are references.
 *
 * If no indices are given, all arguments must be references.
 *
 * @tparam Idx Index types.
 * @param args Arguments vector.
 * @param idx Indices of arguments to check (variadic).
 * @throws std::runtime_error If any specified argument is not a reference.
 */
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

/**
 * @brief Assert that the specified arguments are values.
 *
 * If no indices are given, all arguments must be values.
 *
 * @tparam Idx Index types.
 * @param args Arguments vector.
 * @param idx Indices of arguments to check (variadic).
 * @throws std::runtime_error If any specified argument is not a value.
 */
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

/**
 * @brief Merge @p source into the field @p targetPath of @p event.
 *
 * A shallow merge throws only before touching the event (a type mismatch is detected first), so it runs in place.
 * A deep merge can hit a nested type conflict half-way, so it runs on a copy of the target that replaces the
 * field only on success.
 *
 * @param event Event to modify.
 * @param targetPath JSON pointer path of the target field, which must exist.
 * @param source Value merged into the target.
 * @param recursive Deep merge when true.
 * @throws std::runtime_error On a type conflict; the event is left untouched.
 */
inline void
mergeIntoField(const base::Event& event, std::string_view targetPath, const json::Json& source, bool recursive)
{
    if (!recursive)
    {
        event->merge(json::NOT_RECURSIVE, source, targetPath);
        return;
    }

    auto merged = event->getJson(targetPath).value();
    merged.merge(json::RECURSIVE, source);
    event->set(targetPath, merged);
}

/**
 * @brief Parse the optional trailing mode literal of a helper that accepts `'deep'`.
 *
 * @param args Arguments vector.
 * @param index Position of the optional mode argument.
 * @return true if the argument is present (and is the literal 'deep').
 * @throws std::runtime_error if the argument is present but is not the literal 'deep'.
 */
inline bool parseDeepMode(const std::vector<OpArg>& args, size_t index)
{
    if (args.size() <= index)
    {
        return false;
    }

    assertValue(args, index);
    std::string mode;
    if (std::static_pointer_cast<Value>(args[index])->value().getString(mode) != json::RetGet::Success
        || mode != "deep")
    {
        throw std::runtime_error(
            fmt::format("Expected the literal 'deep' as parameter {} but got {}", index + 1, args[index]->str()));
    }

    return true;
}

} // namespace builder::builders::utils

#endif // BUILDER_BUILDERS_UTILS_HPP

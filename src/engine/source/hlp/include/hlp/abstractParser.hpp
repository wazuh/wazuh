#ifndef _HLP_ABS_PARSER_HPP
#define _HLP_ABS_PARSER_HPP

#include <functional>
#include <string_view>
#include <type_traits>
#include <vector>

/**
 * @brief Contains the Parser and Result types for the parser combinators.
 *
 */
namespace hlp::abs
{
// TODO: Split trace from extracted value and build a single Result and Parse definition for logpar and hlp.

template<typename T>
class Result
{
public:
    using Nested = std::vector<Result>;
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    static_assert(std::is_move_constructible_v<T>, "T must be move constructible");

private:
    T m_value;
    std::string_view m_remaining;
    std::string_view m_trace;
    bool m_success;
    bool m_hasValue;
    Nested m_nested;

public:
    Result() = default;
    ~Result() = default;

    /**
     * @brief Construct a new Result object
     *
     * @param value Extracted value.
     * @param remaining Remaining string not consumed by the parser.
     * @param success If the parser was successful.
     * @param trace Contextual information about the parser failure (name)
     * @param hasValue If the parser has a value.
     * @param nested Nested results if any.
     */
    Result(T&& value,
           std::string_view remaining,
           bool success,
           std::string_view trace,
           bool hasValue,
           Nested&& nested = {})
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
        , m_nested(std::move(nested))
    {
    }

    /**
     * @brief Construct a new Result object
     *
     * @tparam Nested
     * @param value Extracted value.
     * @param remaining Remaining string not consumed by the parser.
     * @param success If the parser was successful.
     * @param trace Contextual information about the parser failure (name)
     * @param hasValue If the parser has a value.
     * @param nested Nested results if any.
     */
    template<typename... Nested>
    Result(
        T&& value, std::string_view remaining, bool success, std::string_view trace, bool hasValue, Nested&&... nested)
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
    {
        m_nested.reserve(sizeof...(Nested));
        (m_nested.emplace_back(std::move(nested)), ...);
    }

    Result(const Result& other) = default;
    Result(Result&& other) noexcept = default;

    /**
     * @brief Returns true if the parser was successful.
     *
     * @return true
     * @return false
     */
    bool success() const { return m_success; }

    /**
     * @brief Returns true if the parser failed.
     *
     * @return true
     * @return false
     */
    bool failure() const { return !m_success; }

    /**
     * @brief Returns the remaining string not consumed by the parser.
     *
     * @return std::string_view
     */
    std::string_view remaining() const { return m_remaining; }

    /**
     * @brief Returns true if the parser has extracted a value.
     *
     * @return true
     * @return false
     */
    bool hasValue() const { return m_hasValue; }

    /**
     * @brief Returns the extracted value.
     *
     * @return const T&
     */
    const T& value() const { return m_value; }

    /**
     * @brief Returns the nested results.
     *
     * @return const Nested&
     */
    const Nested& nested() const { return m_nested; }

    /**
     * @brief Returns the contextual information about the parser failure (name).
     *
     * @return std::string_view
     */
    std::string_view trace() const { return m_trace; }
};

template<typename T>
auto makeSuccess(std::string_view remaining)
{
    return Result<T>({}, remaining, true, {}, false);
}

template<typename T>
auto makeSuccess(T&& value, std::string_view remaining)
{
    return Result<T>(std::move(value), remaining, true, {}, true);
}

template<typename T, typename... Nested>
auto makeSuccess(T&& value, std::string_view remaining, Nested&&... nested)
{
    return Result<T>(std::move(value), remaining, true, {}, true, std::move(nested)...);
}

template<typename T>
auto makeSuccess(std::string_view remaining, typename Result<T>::Nested&& nested)
{
    return Result<T>({}, remaining, true, {}, false, std::move(nested));
}

template<typename T, typename... Nested>
auto makeSuccess(std::string_view remaining, Nested&&... nested)
{
    return Result<T>({}, remaining, true, {}, false, std::move(nested)...);
}

template<typename T>
auto makeFailure(std::string_view remaining, std::string_view trace)
{
    return Result<T>({}, remaining, false, trace, false);
}

template<typename T>
auto makeFailure(std::string_view remaining, std::string_view trace, typename Result<T>::Nested&& nested)
{
    return Result<T>({}, remaining, false, trace, false, std::move(nested));
}

template<typename T, typename... Nested>
auto makeFailure(std::string_view remaining, std::string_view trace, Nested&&... nested)
{
    return Result<T>({}, remaining, false, trace, false, std::move(nested)...);
}

template<typename T>
using Parser = std::function<Result<T>(std::string_view)>;
} // namespace hlp::abs

#endif // _HLP_ABS_PARSER_HPP

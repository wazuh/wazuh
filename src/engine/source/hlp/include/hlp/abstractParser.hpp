#ifndef _HLP_ABS_PARSER_HPP
#define _HLP_ABS_PARSER_HPP

#include <functional>
#include <string_view>
#include <type_traits>
#include <vector>

namespace hlp::abs
{
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

    Result(T&& value, std::string_view remaining, bool success, std::string_view trace, bool hasValue)
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
        , m_nested()
    {
    }

    Result(T&& value, std::string_view remaining, bool success, std::string_view trace, bool hasValue, Nested&& nested)
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
        , m_nested(std::move(nested))
    {
    }

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

    Result(const Result& other)
        : m_value(other.m_value)
        , m_remaining(other.m_remaining)
        , m_trace(other.m_trace)
        , m_success(other.m_success)
        , m_hasValue(other.m_hasValue)
        , m_nested(other.m_nested)
    {
    }

    Result(Result&& other) noexcept
        : m_value(std::move(other.m_value))
        , m_remaining(std::move(other.m_remaining))
        , m_trace(std::move(other.m_trace))
        , m_success(std::move(other.m_success))
        , m_hasValue(std::move(other.m_hasValue))
        , m_nested(std::move(other.m_nested))
    {
    }

    bool success() const { return m_success; }
    bool failure() const { return !m_success; }

    std::string_view remaining() const { return m_remaining; }

    bool hasValue() const { return m_hasValue; }
    const T& value() const { return m_value; }

    const Nested& nested() const { return m_nested; }

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

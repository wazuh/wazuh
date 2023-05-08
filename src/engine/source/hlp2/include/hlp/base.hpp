#ifndef _HLP_BASE_HPP
#define _HLP_BASE_HPP

#include <optional>
#include <string_view>
#include <variant>

#include <fmt/format.h>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>

namespace hlp::internal
{

/**
 * @brief Returns error if index is out of range
 *
 * @tparam T type of the parsec::Result when error
 * @param text input string
 * @param index index to check
 * @return std::optional<parsec::Result<T>> Result<T> if index is out of range,
 * std::nullopt otherwise
 */
//template<typename T>
//std::optional<parsec::Result<T>> eofError(std::string_view txt, size_t idx)
//{
//    if (idx >= txt.size())
//    {
//        return parsec::makeError<T>("Unexpected EOF", idx);
//    }
//    return std::nullopt;
//}

/**
 * @brief Returns the substring of the input string starting at the given index until the
 * stop string or error.
 *
 * If stop is empty, the substring will be the rest of the input string.
 * If stop is not found, an error will be returned.
 *
 * @pre index < text.size()
 *
 * @tparam T type of the parsec::Result when error
 * @param txt input string
 * @param index starting index
 * @param end stop string
 * @return std::variant<std::string_view, parsec::Result<T>> the substring or error
 */
template<typename T>
std::optional<std::string_view>
stopAux(const parsec::ParserState& state, const std::string& end)
{
    auto data = state.getRemainingData();
    if (end.empty())
    {
        return data;
    }

    auto pos = data.find(end);
    if (pos == std::string::npos)
    {
        return std::nullopt;
    }

    return data.substr(0, pos);
}

template<typename T>
std::variant<std::string_view, parsec::ResultP<T>>
stop(const parsec::ParserState& state, const std::list<std::string>& end)
{
    for (const auto& e : end)
    {
        auto res = stopAux<T>(state, e);
        if (res.has_value())
        {
            return res.value();
        }
    }

    if (state.isTraceEnabled())
    {
        auto msg = fmt::format("Unable to stop at '{}' from '{}'", fmt::join(end, ", "), state.getRemainingData());
        return parsec::ResultP<T>::failure(msg, state.getOffset());
    }
    return parsec::ResultP<T>::failure();

}

/**
 * @brief Checks that index is not out of range and returns the substring of the input
 * string to the stop string if defined or the rest of the string.
 *
 * If index is out of range, a Result<T> is returned with an error.
 * If stop is defined and not found, a Result<T> is returned with an error.
 *
 * @tparam T type of the parsec::Result when error
 * @param txt input string
 * @param idx starting index
 * @param end stop optional
 * @return std::variant<std::string_view, parsec::Result<T>> the substring or error
 */
template<typename T>
std::variant<std::string_view, parsec::ResultP<T>>
preProcess(const parsec::ParserState& state, const Stop& end)
{
    if (state.getRemainingSize() == 0)
    {
       if (state.isTraceEnabled())
        {
            return parsec::ResultP<T>::failure(parsec::TraceP("Unexpected EOF", state.getOffset()));
        }
        return parsec::ResultP<T>::failure();
    }

    if (!end.empty())
    {
        auto res = stop<T>(state, end);
        if (std::holds_alternative<parsec::ResultP<T>>(res))
        {
            return std::get<parsec::ResultP<T>>(res);
        }
        return std::get<std::string_view>(res);
    }

    return state.getRemainingData();
}
} // namespace hlp::internal

#endif // _HLP_BASE_HPP

#ifndef _HLP_BASE_HPP
#define _HLP_BASE_HPP

#include <optional>
#include <string_view>
#include <variant>

#include <hlp/parsec.hpp>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

/**
 * @brief Returns error if index is out of range
 *
 * @tparam T type of the parsec::Result when error
 * @param text input string
 * @param index index to check
 * @return std::optional<parsec::Result<T>> Result<T> if index is out of range,
 * std::nullopt otherwise
 */
template<typename T>
std::optional<parsec::Result<T>> eofError(std::string_view txt, size_t idx)
{
    if (idx >= txt.size())
    {
        return parsec::makeError<T>("Unexpected EOF", txt, idx);
    }
    return std::nullopt;
}

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
std::variant<std::string_view, parsec::Result<T>>
stop(std::string_view txt, size_t idx, std::string_view end)
{
    if (end.empty())
    {
        return txt.substr(idx);
    }

    auto pos = txt.find(txt, idx);
    if (pos == std::string::npos)
    {
        return parsec::makeError<T>(fmt::format("Unable to stop at '{}'", txt), txt, idx);
    }

    return txt.substr(idx, pos);
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
std::variant<std::string_view, parsec::Result<T>>
preProcess(std::string_view txt, size_t idx, Stop end)
{
    auto eof = eofError<T>(txt, idx);
    if (eof.has_value())
    {
        return eof.value();
    }

    std::string_view fp = txt;
    if (end.has_value())
    {
        auto res = stop<T>(txt, idx, end.value());
        if (std::holds_alternative<parsec::Result<T>>(res))
        {
            return std::get<parsec::Result<T>>(res);
        }
        else
        {
            fp = std::get<std::string_view>(res);
        }
    }
    return fp;
}

#endif // _HLP_BASE_HPP

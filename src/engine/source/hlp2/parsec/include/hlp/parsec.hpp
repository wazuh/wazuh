#ifndef _PARSEC_HPP_
#define _PARSEC_HPP_

#include <functional>
#include <list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>

// TODO: check error messages concatenation

/**
 * @brief Contains the parser combinators and parser types
 *
 */
namespace parsec
{
/****************************************************************************************
 * Type definitions
 ****************************************************************************************/
/**
 * @brief Return type of error
 *
 * Encapsulates the error message to avoid variant conflicts
 */
struct Error
{
    std::string msg;
    operator std::string() const { return msg; }
};

/**
 * @brief Return type of parser
 *
 * @tparam T type of the contained value
 */
template<typename T>
class Result
{
private:
    bool init = false;
    void initialized() const
    {
        if (!init)
        {
            throw std::runtime_error("Result not initialized");
        }
    }

public:
    /* Error or value */
    std::variant<T, Error> res;
    /* Index pointing to the next character not consumed by the parser */
    size_t index;
    /* Text parsed */
    std::string_view text;

    Result() = default;
    Result(std::variant<T, Error> valOrErr, std::string_view txt, size_t idx)
        : res {valOrErr}
        , index {idx}
        , text {txt}
        , init {true}
    {
    }

    /**
     * @brief Check if the result is a success
     *
     * @return true if res contains a value
     * @return false if res contains an error
     * @throw std::runtime_error if the result is not initialized
     */
    bool success() const
    {
        initialized();
        return std::holds_alternative<T>(res);
    }

    /**
     * @brief Check if the result is a failure
     *
     * @return true if res contains an error
     * @return false if res contains a value
     * @throw std::runtime_error if the result is not initialized
     */
    bool failure() const
    {
        initialized();
        return std::holds_alternative<Error>(res);
    }

    /**
     * @brief Check if the result is a success
     *
     * @return true if res contains a value
     * @return false if res contains an error
     * @throws std::runtime_error if the result is not initialized
     */
    operator bool() const
    {
        initialized();
        return success();
    }

    /**
     * @brief Get the value
     *
     * @return T& the value
     *
     * @pre init == true && success() == true
     * @throw std::bad_variant_access if success() == false
     * @throw std::runtime_error if init == false
     */
    T value() const
    {
        initialized();
        return std::get<T>(res);
    }

    /**
     * @brief Get the error
     *
     * @return Error& the error
     *
     * @pre init == true && failure() == true
     * @throw std::bad_variant_access if failure() == false
     * @throw std::runtime_error if the result is not initialized
     */
    Error error() const
    {
        initialized();
        return std::get<Error>(res);
    }
};

/**
 * @brief Create a success result
 *
 * @tparam T type of the value returned by the parser
 * @param value value returned by the parser
 * @param text text that was parsed
 * @param index index pointing to the next character not consumed by the parser
 * @return Result<T> success result
 */
template<typename T>
auto makeSuccess(T value, std::string_view text, size_t index)
{
    return Result<T> {value, text, index};
}

/**
 * @brief Create a failure result
 *
 * @tparam T type of the value returned by the parser
 * @param error error message
 * @param text text that was parsed
 * @param index index pointing to the next character not consumed by the parser
 * @return Result<T> failure result
 */
template<typename T>
auto makeError(const std::string& error, std::string_view text, size_t index)
{
    return Result<T> {Error {error}, text, index};
}

/**
 * @brief Parser type
 *
 * A parser is a function that takes a string_view and an index pointing to the next
 * character to parse, and returns a Result<T> where T is the type of the value returned
 * by the parser. Depending if the parser succeeded or failed, the Result<T> will contain
 * either a value or an error.
 *
 * @tparam T value returned by the parser
 */
template<typename T>
using Parser = std::function<Result<T>(std::string_view, size_t)>;

/****************************************************************************************
 * Parser combinators
 ****************************************************************************************/

/**
 * @brief Makes parser optional. Always succeeds, returning the value of the parser if it
 * succeeds, or the default value if it fails.
 *
 * @tparam T type of the value returned by the parser
 * @param p parser
 * @return Parser<T> Combined parser
 */
template<typename T>
Parser<T> opt(const Parser<T>& p)
{
    return [=](std::string_view s, size_t i)
    {
        auto res = p(s, i);
        if (res.success())
        {
            return res;
        }
        else
        {
            return makeSuccess<T>({}, s, i);
        }
    };
}

/**
 * @brief Creates a parser that returns result of the first parser and ignores the result
 * of the second. If any of the parsers fails, the result will be a failure.
 *
 * @tparam L type of the value returned by the first parser
 * @tparam R type of the value returned by the second parser
 * @param l first parser
 * @param r second parser
 * @return Parser<L> Combined parser
 */
template<typename L, typename R>
Parser<L> operator<<(const Parser<L>& l, const Parser<R>& r)
{
    Parser<L> fn = [l, r](std::string_view s, size_t i)
    {
        auto resL = l(s, i);
        if (resL.failure())
        {
            return resL;
        }

        auto resR = r(s, resL.index);
        if (resR.failure())
        {
            return makeError<L>(resR.error(), s, resR.index);
        }

        return makeSuccess(resL.value(), s, resR.index);
    };

    return fn;
}

/**
 * @brief Creates a parser that returns result of the second parser and ignores the result
 * of the first. If any of the parsers fails, the result will be a failure.
 *
 * @tparam L type of the value returned by the first parser
 * @tparam R type of the value returned by the second parser
 * @param l first parser
 * @param r second parser
 * @return Parser<R> Combined parser
 */
template<typename L, typename R>
Parser<R> operator>>(const Parser<L>& l, const Parser<R>& r)
{
    Parser<R> fn = [l, r](std::string_view s, size_t i)
    {
        auto resL = l(s, i);
        if (resL.failure())
        {
            return makeError<R>(resL.error(), s, resL.index);
        }

        return r(s, resL.index);
    };

    return fn;
}

/**
 * @brief Creates a parser that returns the result of the first parser if it succeeds, or
 * the result of the second parser if the first fails.
 *
 * @tparam T type of the value returned
 * @param l first parser
 * @param r second parser
 * @return Parser<std::variant<L, R>> Combined parser
 */
template<typename T>
Parser<T> operator|(const Parser<T>& l, const Parser<T>& r)
{
    return [l, r](std::string_view s, size_t i)
    {
        auto resL = l(s, i);
        if (resL.success())
        {
            return resL;
        }

        auto resR = r(s, i);
        if (resR.success())
        {
            return resR;
        }

        return makeError<T>(resL.error().msg + " or " + resR.error().msg, s, i);
    };
}

/**
 * @brief Creates a parser that returns a tuple of the results of the two parsers. If any
 * of the parsers fails, the result will be a failure.
 *
 * @tparam L type of the value returned by the first parser
 * @tparam R type of the value returned by the second parser
 * @param l first parser
 * @param r second parser
 * @return Parser<std::tuple<L, R>> Combined parser
 */
template<typename L, typename R>
Parser<std::tuple<L, R>> operator&(const Parser<L>& l, const Parser<R>& r)
{
    return [l, r](std::string_view s, size_t i)
    {
        auto resL = l(s, i);
        if (resL.failure())
        {
            return makeError<std::tuple<L, R>>(resL.error(), s, resL.index);
        }
        auto resR = r(s, resL.index);
        if (resR.failure())
        {
            return makeError<std::tuple<L, R>>(resR.error(), s, resR.index);
        }
        return makeSuccess<std::tuple<L, R>>(
            std::make_tuple(resL.value(), resR.value()), s, resR.index);
    };
}

/**
 * @brief Creates a parser that executes the function f on the result of the given parser
 * and returns the result of the function. If the given parser fails, the result will be a
 * failure.
 *
 * @tparam Tx type of the value returned by the function
 * @tparam T type of the value returned by the parser
 * @param f function to execute
 * @param p parser to execute
 * @return Parser<Tx> Combined parser
 */
template<typename Tx, typename T>
Parser<Tx> fmap(std::function<Tx(T)> f, const Parser<T>& p)
{
    return [f, p](std::string_view s, size_t i)
    {
        auto res = p(s, i);
        if (res.failure())
        {
            return makeError<Tx>(res.error(), s, res.index);
        }
        return makeSuccess<Tx>(f(res.value()), s, res.index);
    };
}

/* Monadic binding helper type */
template<typename Tx, typename T>
using M = std::function<Parser<Tx>(T)>;

/**
 * @brief Creates a parser that creates a new parser from the result of the given parser
 * using the factory function f. If the given parser fails, the result will be a failure.
 *
 * @tparam Tx type of the value returned by the parser created by the factory function
 * @tparam T type of the value returned by the given parser
 * @param p parser to execute
 * @param f factory function to create a new parser
 * @return Parser<Tx> Combined parser
 */
template<typename Tx, typename T>
Parser<Tx> operator>>=(const Parser<T>& p, M<Tx, T> f)
{
    return [p, f](std::string_view s, size_t i)
    {
        auto res = p(s, i);
        if (res.failure())
        {
            return makeError<Tx>(res.error(), s, res.index);
        }
        auto newParser = f(res.value());
        return newParser(s, res.index);
    };
}

/* List of values helper type */
template<typename T>
using Values = std::list<T>;

/**
 * @brief Creates a parser that executes the given parser zero or more times and returns a
 * list of the results. This parser will never fail.
 *
 * @tparam T type of the value returned by the given parser
 * @param p parser to execute
 * @return Parser<Values<T>> Combined parser
 */
template<typename T>
Parser<Values<T>> many(const Parser<T>& p)
{
    return [p](std::string_view s, size_t i)
    {
        Values<T> values {};
        auto innerI = i;
        while (true)
        {
            auto innerRes = p(s, innerI);
            if (innerRes.failure())
            {
                break;
            }
            values.push_back(innerRes.value());
            innerI = innerRes.index;
        }

        return makeSuccess<Values<T>>(values, s, innerI);
    };
}

/**
 * @brief Creates a parser that executes the given parser one or more times and returns a
 * list of the results. This parser will fail if the given parser does not succeed at
 * least once.
 *
 * @tparam T type of the value returned by the given parser
 * @param p parser to execute
 * @return Parser<Values<T>> Combined parser
 */
template<typename T>
Parser<Values<T>> many1(const Parser<T>& p)
{
    auto manyP = many(p);
    return [manyP, p](std::string_view s, size_t i)
    {
        auto firstRes = p(s, i);
        if (firstRes.failure())
        {
            return makeError<Values<T>>(firstRes.error(), s, firstRes.index);
        }

        Values<T> values {firstRes.value()};
        auto res = manyP(s, firstRes.index);
        values.splice(values.end(), res.value());
        return makeSuccess<Values<T>>(values, s, res.index);
    };
}

/**
 * @brief Creates a parser that adds a tag to the result of the given parser. If the given
 * parser fails, the result will be a failure.
 *
 * @tparam T type of the value returned by the given parser
 * @tparam Tag type of the tag
 * @param p parser to execute
 * @param tag tag to add
 * @return Parser<std::tuple<T, Tag>> Combined parser
 */
template<typename T, typename Tag>
Parser<std::tuple<T, Tag>> tag(const Parser<T>& p, Tag tag)
{
    return fmap<std::tuple<T, Tag>, T>([tag](T val) { return std::make_tuple(val, tag); },
                                       p);
}

/**
 * @brief Creates a parser that replaces the result of the given parser with the given
 * tag. If the given parser fails, the result will be a failure.
 *
 * @tparam T type of the value returned by the given parser
 * @tparam Tag type of the tag
 * @param p parser to execute
 * @param tag tag to replace the result with
 * @return Parser<Tag> Combined parser
 */
template<typename T, typename Tag>
Parser<Tag> replace(const Parser<T>& p, Tag tag)
{
    return fmap<Tag, T>([tag](T) { return tag; }, p);
}

} // namespace parsec

#endif // _PARSEC_HPP_

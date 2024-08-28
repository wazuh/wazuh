#ifndef _PARSEC_HPP_
#define _PARSEC_HPP_

#include <functional>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

#include <fmt/format.h>

/**
 * @brief Contains the parser combinators and parser types
 *
 */
namespace parsec
{
/****************************************************************************************
 * Type definitions
 ****************************************************************************************/
class Trace
{
public:
    using messageT = std::optional<std::string>;
    using nestedTracesT = std::optional<std::vector<Trace>>;

private:
    bool m_success;
    size_t m_index;
    messageT m_message;
    nestedTracesT m_innerTraces;

public:
    Trace() = default;
    ~Trace() = default;
    Trace(bool success, size_t index, messageT&& message, nestedTracesT&& innerTraces)
        : m_success(success)
        , m_index(index)
        , m_message(std::move(message))
        , m_innerTraces(std::move(innerTraces))
    {
    }
    Trace(const Trace& other)
        : m_success(other.m_success)
        , m_index(other.m_index)
        , m_message(other.m_message)
        , m_innerTraces(other.m_innerTraces)
    {
    }
    Trace(Trace&& other) noexcept
        : m_success(std::move(other.m_success))
        , m_index(std::move(other.m_index))
        , m_message(std::move(other.m_message))
        , m_innerTraces(std::move(other.m_innerTraces))
    {
    }
    Trace& operator=(const Trace& other)
    {
        m_success = other.m_success;
        m_index = other.m_index;
        m_message = other.m_message;
        m_innerTraces = other.m_innerTraces;
        return *this;
    }
    Trace& operator=(Trace&& other) noexcept
    {
        m_success = std::move(other.m_success);
        m_index = std::move(other.m_index);
        m_message = std::move(other.m_message);
        m_innerTraces = std::move(other.m_innerTraces);
        return *this;
    }

    bool operator==(const Trace& other) const
    {
        return m_success == other.m_success && m_index == other.m_index && m_message == other.m_message
               && m_innerTraces == other.m_innerTraces;
    }
    bool operator!=(const Trace& other) const { return !(*this == other); }

    bool success() const { return m_success; }
    size_t index() const { return m_index; }
    const messageT& message() const { return m_message; }
    messageT&& message() { return std::move(m_message); }
    const nestedTracesT& innerTraces() const { return m_innerTraces; }
    nestedTracesT&& innerTraces() { return std::move(m_innerTraces); }
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
    /* value */
    std::optional<T> m_value;
    /* trace */
    Trace m_trace;

public:
    Result() = default;
    ~Result() = default;
    Result(std::optional<T>&& value, Trace&& trace)
        : m_value {std::move(value)}
        , m_trace {std::move(trace)}

    {
    }
    Result(const Result<T>& other)
        : m_value {other.m_value}
        , m_trace {other.m_trace}
    {
    }
    Result(Result<T>&& other) noexcept
        : m_value {std::move(other.m_value)}
        , m_trace {std::move(other.m_trace)}
    {
    }
    Result<T>& operator=(const Result<T>& other)
    {
        m_value = other.m_value;
        m_trace = other.m_trace;
        return *this;
    }
    Result<T>& operator=(Result<T>&& other) noexcept
    {
        m_value = std::move(other.m_value);
        m_trace = std::move(other.m_trace);
        return *this;
    }

    bool operator==(const Result<T>& other) const { return m_value == other.m_value && m_trace == other.m_trace; }
    bool operator!=(const Result<T>& other) const { return !(*this == other); }

    /**
     * @brief Check if the result is a success
     *
     * @return true if res contains a value
     * @return false if res contains an error
     * @throw std::runtime_error if the result is not initialized
     */
    bool success() const { return m_trace.success(); }

    /**
     * @brief Check if the result is a failure
     *
     * @return true if res contains an error
     * @return false if res contains a value
     * @throw std::runtime_error if the result is not initialized
     */
    bool failure() const { return !success(); }

    /**
     * @brief Get the value
     *
     * @return const T& the value
     *
     * @pre success() == true
     * @throws std::bad_optional_access if success() == false
     */
    const T& value() const { return *m_value; }

    /**
     * @brief Get the value
     *
     * @return T&& the value
     *
     * @pre success() == true
     * @throws std::bad_optional_access if success() == false
     */
    T&& value() { return std::move(*m_value); }

    /**
     * @brief Get the error
     *
     * @return const std::string& the error
     *
     * @pre failure() == true
     * @throw std::bad_optional_access if failure() == false
     */
    const std::string& error() const { return m_trace.message().value(); }

    /**
     * @brief Get the trace
     *
     * @return const Trace& the trace
     */
    const Trace& trace() const { return m_trace; }

    /**
     * @brief Get the trace
     *
     * @return Trace&& the trace
     * @warning this object is left in undefined state
     */
    Trace&& trace() { return std::move(m_trace); }

    size_t index() const { return m_trace.index(); }
};

/**
 * @brief Create a success result
 *
 * @tparam T type of the value returned by the parser
 * @param valuePtr value returned by the parser
 * @param index index pointing to the next character not consumed by the parser
 * @param trace optional with trace (if any)
 * @param innerTrace traces of combinated parsers (if any)
 *
 * @return Result<T> success result
 */
template<typename T>
Result<T> makeSuccess(T&& value,
                      size_t index,
                      Trace::messageT&& trace = std::nullopt,
                      Trace::nestedTracesT&& innerTrace = std::nullopt)
{
    return Result<T> {std::make_optional<T>(std::move(value)),
                      Trace {true, index, std::move(trace), std::move(innerTrace)}};
}

/**
 * @brief Create a failure result
 *
 * @tparam T type of the value returned by the parser
 * @param error error message
 * @param index index pointing to the next character not consumed by the parser
 * @param innerTrace traces of combinated parsers (if any)
 *
 * @return Result<T> failure result
 */
template<typename T>
Result<T> makeError(std::string&& error, size_t index, Trace::nestedTracesT&& innerTrace = std::nullopt)
{
    return Result<T> {std::nullopt,
                      Trace {false, index, std::make_optional<std::string>(std::move(error)), std::move(innerTrace)}};
}

inline const Trace& firstError(const Trace& trace)
{
    if (trace.innerTraces().has_value())
    {
        for (const auto& t : trace.innerTraces().value())
        {
            if (!t.success())
            {
                return firstError(t);
            }
        }
    }

    return trace;
}

inline std::list<const Trace*> getLeafErrors(const Trace& trace)
{
    std::list<const Trace*> errors;
    if (trace.innerTraces().has_value())
    {
        for (const auto& t : trace.innerTraces().value())
        {
            auto aux = getLeafErrors(t);
            errors.splice(errors.end(), aux);
        }
    }
    else if (!trace.success())
    {
        errors.push_back(&trace);
    }

    return errors;
}

inline std::string detailedTrace(const Trace& trace, bool last, std::string prefix = "")
{
    std::string tr = prefix;

    tr += last ? "└─" : "├─";

    tr += trace.message().has_value() ? fmt::format("{} at {}\n", trace.message().value(), trace.index())
                                      : "succeeded \n";
    if (trace.innerTraces().has_value())
    {
        auto auxPrefix = prefix + (last ? "   " : "│  ");
        for (auto i = 0; i < trace.innerTraces().value().size() - 1; ++i)
        {
            tr += detailedTrace(trace.innerTraces().value()[i], false, auxPrefix);
        }
        tr += detailedTrace(trace.innerTraces().value().back(), true, auxPrefix);
    }

    return tr;
}

inline std::string formatTrace(std::string_view text, const Trace& trace, size_t debugLvl)
{
    std::string tr;

    // Print the first error as it's probably the most relevant
    auto first = firstError(trace);
    tr = fmt::format("\nMain error: {} at {}\n{}\n{}^\n",
                     first.message().value(),
                     first.index(),
                     text,
                     std::string(first.index(), '-'));

    // Get all leaf errors (errors from our parsers, not combinators)
    auto errors = getLeafErrors(trace);

    if (!errors.empty())
    {
        // Print all errors
        tr += "\nList of errors:\n";
        for (auto e : errors)
        {
            tr += fmt::format(
                "{} at {}\n{}\n{}^\n", e->message().value(), e->index(), text, std::string(e->index(), '-'));
        }
    }

    // Get detailed trace
    if (debugLvl > 0)
    {
        tr += "\nDetailed trace:\n";
        tr += detailedTrace(trace, true);
    }

    return tr;
}

/**
 * @brief Parser type
 *
 * A parser is a function that takes a string_view and an index pointing to the next
 * character to parse, and returns a Result<T> where T is the type of the value
 * returned by the parser. Depending if the parser succeeded or failed, the Result<T>
 * will contain either a value or an error.
 *
 * @tparam T value returned by the parser
 */
template<typename T>
using Parser = std::function<Result<T>(std::string_view, size_t)>;

/****************************************************************************************
 * Traits
 ****************************************************************************************/
namespace traits
{
template<typename T>
struct is_parser : std::false_type
{
};

template<typename T>
struct is_parser<Parser<T>> : std::true_type
{
};

template<typename T, typename R>
struct is_parser_ret : std::false_type
{
};

template<typename T, typename R>
struct is_parser_ret<Parser<T>, R> : std::is_base_of<R, T>
{
};
} // namespace traits

/****************************************************************************************
 * Parser combinators
 ****************************************************************************************/

/**
 * @brief Makes parser optional. Always succeeds, returning the value of the parser if
 * it succeeds, or the default value if it fails.
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
            return makeSuccess<T>(res.value(), res.index(), "OPT(P), P failed", {{res.trace()}});
        }
        else
        {
            return makeSuccess<T>({}, i, "OPT(P), P succeeded", {{res.trace()}});
        }
    };
}

/**
 * @brief Creates a parser that succeeds if the given parser fails, and fails if the
 * given parser succeeds. The resulting parser consumes no input.
 *
 * @tparam T type of the value returned by the parser
 * @param p parser to negate
 * @return Parser<T> Combined parser
 */
template<typename T>
Parser<T> negativeLook(const Parser<T>& p)
{
    return [=](std::string_view s, size_t i)
    {
        auto res = p(s, i);
        if (res.success())
        {
            return makeError<T>("NEG(P), P succeeded", res.index(), {{res.trace()}});
        }
        else
        {
            return makeSuccess<T>({}, i, "NEG(P), P failed", {{res.trace()}});
        }
    };
}

/**
 * @brief Creates a parser that succeeds if the given parser succeeds, and fails if the
 * given parser fails. The resulting parser consumes no input.
 *
 * @tparam T type of the value returned by the parser
 * @param p parser to negate
 * @return Parser<T> Combined parser
 */
template<typename T>
Parser<T> positiveLook(const Parser<T>& p)
{
    return [=](std::string_view s, size_t i)
    {
        auto res = p(s, i);
        if (res.success())
        {
            return makeSuccess<T>({}, i, "POS(P), P succeeded", {{res.trace()}});
        }
        else
        {
            return makeError<T>("POS(P), P failed", res.index(), {{res.trace()}});
        }
    };
}

/**
 * @brief Creates a parser that returns result of the first parser and ignores the
 * result of the second. If any of the parsers fails, the result will be a failure.
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
            return makeError<L>("L<<R, L failed", resL.index(), {{resL.trace()}});
        }

        auto resR = r(s, resL.index());
        if (resR.failure())
        {
            return makeError<L>("L<<R, R failed", resR.index(), {{resL.trace(), resR.trace()}});
        }

        return makeSuccess(resL.value(), resR.index(), "L<<R, succeeded", {{resL.trace(), resR.trace()}});
    };

    return fn;
}

/**
 * @brief Creates a parser that returns result of the second parser and ignores the
 * result of the first. If any of the parsers fails, the result will be a failure.
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
            return makeError<R>("L>>R, L failed", resL.index(), {{resL.trace()}});
        }

        auto resR = r(s, resL.index());
        if (resR.failure())
        {
            return makeError<R>("L>>R, R failed", resR.index(), {{resL.trace(), resR.trace()}});
        }

        return makeSuccess(resR.value(), resR.index(), "L>>R, succeeded", {{resL.trace(), resR.trace()}});
    };

    return fn;
}

/**
 * @brief Creates a parser that returns the result of the first parser if it succeeds,
 * or the result of the second parser if the first fails.
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
            return makeSuccess<T>(resL.value(), resL.index(), "L|R, L succeeded", {{resL.trace()}});
        }

        auto resR = r(s, i);
        if (resR.success())
        {
            return makeSuccess<T>(resR.value(), resR.index(), "L|R, R succeeded", {{resL.trace(), resR.trace()}});
        }

        return makeError<T>("L|R, both failed", i, {{resL.trace(), resR.trace()}});
    };
}

/**
 * @brief Creates a parser that returns a tuple of the results of the two parsers. If
 * any of the parsers fails, the result will be a failure.
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
            return makeError<std::tuple<L, R>>("L&R, L failed", resL.index(), {{resL.trace()}});
        }
        auto resR = r(s, resL.index());
        if (resR.failure())
        {
            return makeError<std::tuple<L, R>>("L&R, R failed", resR.index(), {{resL.trace(), resR.trace()}});
        }

        return makeSuccess<std::tuple<L, R>>(std::make_tuple(resL.value(), resR.value()),
                                             resR.index(),
                                             "L&R, succeeded",
                                             {{resL.trace(), resR.trace()}});
    };
}

/**
 * @brief Creates a parser that executes the function f on the result of the given
 * parser and returns the result of the function. If the given parser fails, the
 * result will be a failure.
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
            return makeError<Tx>("FMAP(P), P failed", res.index(), {{res.trace()}});
        }
        return makeSuccess<Tx>(f(res.value()), res.index(), "FMAP(P), P succeeded", {{res.trace()}});
    };
}

/* Monadic binding helper type */
template<typename Tx, typename T>
using M = std::function<Parser<Tx>(T)>;

/**
 * @brief Creates a parser that creates a new parser from the result of the given
 * parser using the factory function f. If the given parser fails, the result will be
 * a failure.
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
            return makeError<Tx>("P>>=M, P failed", res.index(), {{res.trace()}});
        }

        auto newParser = f(res.value());
        auto res2 = newParser(s, res.index());
        if (res2.failure())
        {
            return makeError<Tx>("P>>=M, M failed", res2.index(), {{res.trace(), res2.trace()}});
        }

        return makeSuccess<Tx>(res2.value(), res2.index(), "P>>=M, succeeded", {{res.trace(), res2.trace()}});
    };
}

/* List of values helper type */
template<typename T>
using Values = std::list<T>;

/**
 * @brief Creates a parser that executes the given parser zero or more times and
 * returns a list of the results. This parser will never fail.
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
        Trace::nestedTracesT traces = std::vector<Trace> {};

        auto innerI = i;
        auto stop = true;
        while (stop)
        {
            auto innerRes = p(s, innerI);
            if (innerRes.failure())
            {
                stop = false;
            }
            else
            {
                values.push_back(innerRes.value());
                innerI = innerRes.index();
            }
            traces.value().push_back(std::move(innerRes.trace()));
        }

        return makeSuccess<Values<T>>(std::move(values), innerI, "MANY(P), succeeded", std::move(traces));
    };
}

/**
 * @brief Creates a parser that executes the given parser one or more times and
 * returns a list of the results. This parser will fail if the given parser does not
 * succeed at least once.
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
            return makeError<Values<T>>("MANY1(P), P failed", firstRes.index(), {{firstRes.trace()}});
        }

        Values<T> values {firstRes.value()};
        auto res = manyP(s, firstRes.index());
        values.splice(values.end(), res.value());
        res.trace().innerTraces().value().insert(res.trace().innerTraces().value().begin(),
                                                 std::move(firstRes.trace()));

        return makeSuccess<Values<T>>(std::move(values), res.index(), "MANY1(P), succeeded", res.trace().innerTraces());
    };
}

/**
 * @brief Creates a parser that adds a tag to the result of the given parser. If the
 given
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
    return fmap<std::tuple<T, Tag>, T>([tag](T val) { return std::make_tuple(val, tag); }, p);
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

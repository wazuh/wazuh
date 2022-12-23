#ifndef _HLP_COMBINATORS_HPP
#define _HLP_COMBINATORS_HPP

#include <functional>
#include <list>
#include <string_view>

#include <hlp/result.hpp>

namespace parsec
{
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
            return makeSuccess<T>(
                res.value(), res.index(), "OPT(P), P failed", res.getTracePtr());
        }
        else
        {
            return makeSuccess<T>({}, i, "OPT(P), P succeeded", res.getTracePtr());
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
            return makeError<L>("L<<R, L failed", resL.index(), resL.getTracePtr());
        }

        auto resR = r(s, resL.index());
        if (resR.failure())
        {
            return makeError<L>(
                "L<<R, R failed", resR.index(), resL.getTracePtr(), resR.getTracePtr());
        }

        return makeSuccess(resL.value(),
                           resR.index(),
                           "L<<R, succeeded",
                           resL.getTracePtr(),
                           resR.getTracePtr());
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
            return makeError<R>("L>>R, L failed", resL.index(), resL.getTracePtr());
        }

        auto resR = r(s, resL.index());
        if (resR.failure())
        {
            return makeError<R>(
                "L>>R, R failed", resR.index(), resL.getTracePtr(), resR.getTracePtr());
        }

        return makeSuccess(resR.value(),
                           resR.index(),
                           "L>>R, succeeded",
                           resL.getTracePtr(),
                           resR.getTracePtr());
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
            return makeSuccess<T>(
                resL.value(), resL.index(), "L|R, L succeeded", resL.getTracePtr());
        }

        auto resR = r(s, i);
        if (resR.success())
        {
            return makeSuccess<T>(resR.value(),
                                  resR.index(),
                                  "L|R, R succeeded",
                                  resL.getTracePtr(),
                                  resR.getTracePtr());
        }

        return makeError<T>(
            "L|R, both failed", i, resL.getTracePtr(), resR.getTracePtr());
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
            return makeError<std::tuple<L, R>>(
                "L&R, L failed", resL.index(), resL.getTracePtr());
        }
        auto resR = r(s, resL.index());
        if (resR.failure())
        {
            return makeError<std::tuple<L, R>>(
                "L&R, R failed", resR.index(), resL.getTracePtr(), resR.getTracePtr());
        }

        return makeSuccess<std::tuple<L, R>>(std::make_tuple(resL.value(), resR.value()),
                                             resR.index(),
                                             "L&R, succeeded",
                                             resL.getTracePtr(),
                                             resR.getTracePtr());
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
            return makeError<Tx>("FMAP(P), P failed", res.index(), res.getTracePtr());
        }
        return makeSuccess<Tx>(
            f(res.value()), res.index(), "FMAP(P), P succeeded", res.getTracePtr());
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
            return makeError<Tx>("P>>=M, P failed", res.index(), res.getTracePtr());
        }

        auto newParser = f(res.value());
        auto res2 = newParser(s, res.index());
        if (res2.failure())
        {
            return makeError<Tx>(
                "P>>=M, M failed", res2.index(), res.getTracePtr(), res2.getTracePtr());
        }

        return makeSuccess<Tx>(res2.value(),
                               res2.index(),
                               "P>>=M, succeeded",
                               res.getTracePtr(),
                               res2.getTracePtr());
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
        Trace::nestedTracesT traces = std::list<std::shared_ptr<Trace>> {};

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
            }
            innerI = innerRes.index();
            traces.value().push_back(innerRes.getTracePtr());
        }

        return makeSuccessFromList<Values<T>>(
            std::move(values), innerI, "MANY(P), succeeded", std::move(traces));
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
            return makeError<Values<T>>(
                "MANY1(P), P failed", firstRes.index(), firstRes.getTracePtr());
        }

        auto index = firstRes.index();

        Values<T> values {};
        Trace::nestedTracesT traces = std::list<std::shared_ptr<Trace>> {};

        values.push_back(firstRes.value());
        traces.value().push_back(firstRes.getTracePtr());

        auto res = manyP(s, index);
        index = res.index();
        auto resTrace = res.getTracePtr();

        values.splice(values.end(), res.value());
        traces.value().splice(traces.value().end(), resTrace->innerTraces().value());

        return makeSuccessFromList<Values<T>>(
            std::move(values), index, "MANY1(P), succeeded", std::move(traces));
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

#endif // PARSEC_HPP

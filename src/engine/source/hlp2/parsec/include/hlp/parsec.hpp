#ifndef _PARSEC_HPP_
#define _PARSEC_HPP_

#include <functional>
#include <list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <fmt/format.h>

/**
 * @brief Contains the parser definition, combinators and parser types
 *
 * - Definition of ParserState, the input for parsers
 * - Definition of TraceP, used for tracing parsers
 * - Definition of ResultP, the result of a parser (success or failure, with optional value and traces)
 * - Definition of Parser, function that takes an ParserState and returns a ResultP
 * - Definition of parser combinator functions
 */
namespace parsec
{

/**
 * @brief Input for parsers
 *
 * Used as input for parsers and the result for stored remaining data with the state of the parser.
 * The input is a string_view that contains the data to be parsed, and a position that points to the next character to
 * be parsed.
 *
 * @warning The input is not the owner of the data, so the data must be kept alive while the input is used.
 */
class ParserState final
{

private:
    std::string_view m_data; ///< The stream of data to be parsed
    std::size_t m_pos;       ///< The current position in the data, pointing to the next character to be parsed
    std::size_t m_maxPos;    ///< The maximum position in the data, this is used to limit the parser to a certain size
    bool m_enableTraces;     ///< Enable traces for the input

public:
    /**
     * @brief Construct a new parser state
     *
     * @param data The data to be parsed
     * @param pos The current position in the data, pointing to the next character to be parsed
     * @param maxPos The maximum position in the data, this is used to limit the parser to a certain size
     * @warning The input is not the owner of the data, so the data must be kept alive while the input is used.
     */
    ParserState(std::string_view data, bool enableTraces = false)
        : m_data(data)
        , m_pos(0)
        , m_maxPos(data.size())
        , m_enableTraces(enableTraces) {};

    /**
     * @brief Advance the current position in the data, pointing to the next character to be parsed
     *
     * @param offset The offset to advance the current position in the data
     * @return ParserState& A reference to the input
     */
    ParserState& advance(std::size_t offset)
    {
        m_pos += offset;
        if (m_pos > m_maxPos)
        {
            throw std::runtime_error(fmt::format("ParserState::advance: The position '{}' is greater than the maximum "
                                                 "position '{}' for the input: '{}'",
                                                 m_pos,
                                                 m_maxPos,
                                                 m_data));
        }
        return *this;
    }

    /**
     * @brief Get the Position in the data where the next character to be parsed is.
     *
     * @return The position in the data where the next character to be parsed is.
     */
    std::size_t getOffset() const { return m_pos; }

    /**
     * @brief Get the original data to be parsed
     *
     * @return The original data to be parsed (position is not taken into account)
     */
    const std::string_view& getData() const { return m_data; }

    /**
     * @brief Get the Remaining Data to be parsed.
     *
     * The remaining data is the data from the current position to the end
     * @return The remaining data to be parsed
     */
    std::string_view getRemainingData() const { return m_data.substr(m_pos); }

    /**
     * @brief Get the remaining size of the data to be parsed
     *
     * @return std::size_t
     */
    std::size_t getRemainingSize() const { return m_maxPos - m_pos; }

    /**
     * @brief Check if the trace is enabled
     * @return bool True if the trace is enabled, false otherwise
     */
    bool isTraceEnabled() const { return m_enableTraces; }
};

/**
 * @brief Trace type
 *
 * Used to trace parsers, it contains the message and the offset where the parser generated the trace.
 */
class TraceP
{
private:
    std::string m_message; ///< The message of the trace (usually the name of the parser and message of the trace)
    std::size_t m_offset;  ///< The offset where the parser generated the trace

public:
    /**
     * @brief Construct a new Trace P object with the message and offset
     *
     * @param message The message of the trace (usually the name of the parser and message of the trace)
     * @param offset The offset where the parser generated the trace
     */
    TraceP(const std::string& message, std::size_t offset)
        : m_message(message)
        , m_offset(offset)
    {
    }

    /**
     * @brief Construct a new Trace P object with the message and offset
     *
     * @param message The message of the trace (usually the name of the parser and message of the trace)
     * @param offset The offset where the parser generated the trace
     */
    TraceP(std::string&& message, std::size_t offset)
        : m_message(std::move(message))
        , m_offset(offset)
    {
    }

    /**
     * @brief Get the message of the trace
     *
     * @return The message of the trace (usually the name of the parser and message of the trace)
     */
    const std::string& getMessage() const { return m_message; }

    /**
     * @brief Get the offset where the parser generated the trace
     *
     * @return std::size_t The offset where the parser generated the trace
     */
    std::size_t getOffset() const { return m_offset; }
};

/**
 * @brief Result type
 *
 * Used to return the result of a parser, it can be successful or not.
 * If the result is successful it has a parserState (with the remaining input) and can have a value or not.
 * If the result is not successful it can have a list of traces.
 *
 * @tparam T The type of the value of the result
 */
template<typename T>
class ResultP final
{
private:
    /**
     * @brief List of traces, is optional and can be empty or have multiple entries if the parser was a chain of parsers
     */
    std::optional<std::list<TraceP>> m_traces;
    std::optional<ParserState> m_parserState; ///< The parser state if the result is successful, empty otherwise.
    std::optional<T> m_value; ///< Value of the successful result, can be empty if the parser does not return any.

    /**************************************************************************
     * Success Constructors
     *
     * The result is successful if m_parserState is set with the remaining input
     * m_value is optional and can be empty, not all parsers return a value
     * m_traces is optional and can be empty or have multiple entries if the parser was a chain of parsers
     *
     **************************************************************************/
    /**
     * @brief Construct a ResultP successful result with no value and no traces
     *
     * @param state The state of parser
     */
    ResultP(ParserState state)
        : m_value()
        , m_traces()
        , m_parserState(state)
    {
    }

    /**
     * @brief Construct a ResultP successful result with a value and no traces
     *
     * @param state The state of parser
     * @param value The value of the result
     */
    ResultP(ParserState state, T&& value)
        : m_value(std::move(value))
        , m_traces()
        , m_parserState(state)
    {
    }

    /**
     * @brief Construct a ResultP successful result with a value and a trace
     *
     * @param state
     * @param value
     * @param trace
     */
    ResultP(ParserState state, T&& value, TraceP&& trace)
        : m_value(std::move(value))
        , m_traces({std::move(trace)})
        , m_parserState(state)
    {
    }

    /**
     * @brief Construct a ResultP successful result with a value and a list of traces
     *
     * @param state
     * @param value
     * @param traces
     */
    ResultP(ParserState state, T&& value, std::list<TraceP>&& traces)
        : m_value(std::move(value))
        , m_traces(std::move(traces))
        , m_parserState(state)
    {
    }

    /**************************************************************************
     * Failure Constructors
     **************************************************************************/
    /**
     * @brief Construct a ResultP failure result with no traces
     */
    ResultP()
        : m_value()
        , m_traces()
        , m_parserState()
    {
    }

    /**
     * @brief Construct a ResultP failure result with a trace
     *
     * @param trace
     */
    ResultP(TraceP&& trace)
        : m_value()
        , m_traces({std::move(trace)})
        , m_parserState()
    {
    }

    /**
     * @brief Construct a ResultP failure result with a list of traces
     *
     * @param traces
     */
    ResultP(std::list<TraceP>&& traces)
        : m_value()
        , m_traces(std::move(traces))
        , m_parserState()
    {
    }

public:
    /**************************************************************************
     * Move Constructors
     **************************************************************************/
    ResultP(ResultP&& other)
        : m_value(std::move(other.m_value))
        , m_traces(std::move(other.m_traces))
        , m_parserState(std::move(other.m_parserState))
    {
    }

    // Move assignment operator
    ResultP& operator=(ResultP&& other)
    {
        m_value = std::move(other.m_value);
        m_traces = std::move(other.m_traces);
        m_parserState = std::move(other.m_parserState);
        return *this;
    }

    /**************************************************************************
     * Copy Constructors
     **************************************************************************/
    ResultP(const ResultP& other)
        : m_value(other.m_value)
        , m_traces(other.m_traces)
        , m_parserState(other.m_parserState)
    {
    }

    // Copy assignment operator
    ResultP& operator=(const ResultP& other)
    {
        m_value = other.m_value;
        m_traces = other.m_traces;
        m_parserState = other.m_parserState;
        return *this;
    }

    /**************************************************************************
     * Operations of result
     **************************************************************************/
    /**
     * @brief Check if the result is successful (has a remaining input)
     *
     * @return true if the result is successful, false otherwise
     */
    bool isSuccessful() const { return m_parserState.has_value(); }

    /**
     * @brief Operator bool, check if the result is successful (has a remaining input)
     *
     * @return true if the result is successful, false otherwise
     */
    operator bool() const { return isSuccessful(); }

    /**
     * @brief Get the parser state of the result. The result must be successful
     *
     * @return The state of parser
     * @throw std::runtime_error if the result is not successful
     */
    const ParserState& getParserState() const
    {
        if (!m_parserState.has_value())
        {
            throw std::runtime_error("ResultP::getParserState() called on a failed result");
        }
        return m_parserState.value();
    }

    /**************************************************************************
     * Operations of trace
     **************************************************************************/
    /**
     * @brief Check if the result has traces
     * @return true if the result has traces, false otherwise
     */
    bool hasTraces() const { return m_traces.has_value(); }

    /**
     * @brief Pop the traces of the result. The result must have traces
     *
     * The result is moved, so it is not valid after this operation
     * @return The traces of the result
     * @throw std::runtime_error if the result has no traces
     */
    std::list<TraceP> popTraces()
    {
        if (!m_traces.has_value())
        {
            throw std::runtime_error("ResultP::popTraces() called on a result with no traces");
        }
        auto traces = std::move(m_traces.value());
        m_traces.reset();
        return std::move(traces);
    }

    /**
     * @brief Concatenate the traces of the result with the traces of another result
     *
     * @tparam U The type of the other result
     * @param other The other result
     * @return ResultP& A reference to the result
     */
    template<typename U>
    ResultP& concatenateTraces(ResultP<U>&& other)
    {
        if (other.hasTraces())
        {
            if (!m_traces.has_value())
            {
                m_traces = std::move(other.popTraces());
            }
            else
            {
                m_traces.value().splice(m_traces.value().end(), other.popTraces());
            }
        }
        return *this;
    }

    /**
     * @brief Concatenate the traces of the result with a trace
     *
     * @param otherTrace The other trace
     * @return ResultP& A reference to the result
     */
    ResultP& concatenateTraces(TraceP&& otherTraces)
    {
        if (m_traces.has_value())
        {
            m_traces.value().push_back(std::move(otherTraces));
        }
        else
        {
            m_traces = std::list<TraceP>({std::move(otherTraces)});
        }
        return *this;
    }

    /**************************************************************************
     * Operations of value
     **************************************************************************/
    /**
     * @brief Check if the result has a value
     * @return true if the result has a value, false otherwise
     */
    bool hasValue() const { return m_value.has_value(); }

    /**
     * @brief Pop the value of the result. The result must have a value
     *
     * The result is moved, so it is not valid after this operation
     * The value is moved, not the optional value.
     * @return The value of the result
     * @throw std::runtime_error if the result has no value
     */
    T popValue()
    {
        if (!m_value.has_value())
        {
            throw std::runtime_error("ResultP::popValue() called on a result with no value");
        }
        auto retval = std::move(m_value.value());
        m_value.reset();
        return std::move(retval);
    }

    /**************************************************************************
     * Static constructors
     **************************************************************************/
    /**
     * @brief Create a successful result
     *
     * @param state The parser state after the parsing
     * @return ResultP<T> The successful result with no value
     *
     */
    static ResultP<T> success(const ParserState& state) { return ResultP<T>(state); }

    /**
     * @brief Create a successful result with a value
     *
     * @param state The parser state after the parsing
     * @param value The value
     * @return ResultP<T> The successful result with a value
     */
    static ResultP<T> success(const ParserState& state, T&& value) { return ResultP<T>(state, std::move(value)); }

    /**
     * @brief Create a successful result with a value and a trace
     *
     * @param state The parser state after the parsing
     * @param value The value
     * @param trace The trace
     * @return ResultP<T> The successful result with a value and a trace
     */
    static ResultP<T> success(const ParserState& state, T&& value, TraceP&& trace)
    {
        return ResultP<T>(state, std::move(value), std::move(trace));
    }

    /**
     * @brief Create a successful result with a value and a list of traces
     *
     * @param state The parser state after the parsing
     * @param value The value
     * @param traces The list of traces
     * @return ResultP<T> The successful result with a value and a list of traces
     */
    static ResultP<T> success(const ParserState& state, T&& value, std::list<TraceP>&& traces)
    {
        return ResultP<T>(state, std::move(value), std::move(traces));
    }

    /**
     * @brief Create a failed result
     *
     * @return ResultP<T> The failed result
     */
    static ResultP<T> failure() { return ResultP<T>(); }

    /**
     * @brief Create a failed result with a trace
     *
     * @param trace The trace
     * @return ResultP<T> The failed result with a trace
     */
    static ResultP<T> failure(TraceP&& trace) { return ResultP<T>(std::move(trace)); }

    /**
     * @brief Create a failed result with a list of traces
     *
     * @param traces The list of traces
     * @return ResultP<T> The failed result with a list of traces
     */
    static ResultP<T> failure(std::list<TraceP>&& traces) { return ResultP<T>(std::move(traces)); }
};

/**
 * @brief Parser type
 *
 * A parser is a function that takes a parser state as parameter, representing the input
 * character to parse and config, and returns a ResultP<T> where T is the type of the value
 * returned by the parser. The ResultP<T> contains the remaining input (parser state), the value
 * returned by the parser (if any), and a list of traces (if any).
 * The ResultP<T> can be a success or a failure and can contain a value and traces or not.
 * The parser can be a lambda function, a function, or a functor.
 * @tparam T value returned by the parser (if any)
 */
template<typename T>
using Parser = std::function<ResultP<T>(ParserState)>;

/****************************************************************************************
 * Parser combinators
 ****************************************************************************************/
/**
 * @brief Makes parser optional. Always succeeds, returning the value of the parser if
 * it succeeds, or the default value if it fails.
 *
 * @tparam T type of the value returned by the parser
 * @param optParser The parser to make optional
 * @return Parser<T> Combined parser
 */
template<typename T>
Parser<T> opt(const Parser<T>& optParser)
{
    return [=](const ParserState& state) -> ResultP<T>
    {
        {
            auto result = optParser(state);

            if (state.isTraceEnabled())
            {
                result.concatenateTraces(result
                                             ? TraceP("Optional parser succeeded", result.getParserState().getOffset())
                                             : TraceP("Optional parser failed", state.getOffset()));
            }

            if (result)
            {
                return result;
            }
            return ResultP<T>::success(state);
        };
    }
}

/**
 * @brief Creates a parser that returns result of the first parser and ignores the
 * result of the second. If any of the parsers fails, the result will be a failure.
 *
 * @tparam L type of the value returned by the first parser
 * @tparam R type of the value returned by the second parser
 * @param l first parser (left operand)
 * @param r second parser (right operand)
 * @return Parser<L> Combined parser
 */
template<typename L, typename R>
Parser<L> operator<<(const Parser<L>& l, const Parser<R>& r)
{
    Parser<L> fn = [l, r](const ParserState& state) -> ResultP<L>
    {
        auto resultL = l(state);

        if (!resultL)
        {
            if (state.isTraceEnabled())
            {
                resultL.concatenateTraces(TraceP("L<<R, L failed", state.getOffset()));
            }
            return resultL;
        }

        auto resultR = r(resultL.getParserState());

        if (!resultR)
        {
            if (state.isTraceEnabled())
            {
                auto offset = resultL.getParserState().getOffset();
                return ResultP<L>::failure()
                    .concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenate(TraceP("L<<R, R failed", offset));
            }
            return ResultP<L>::failure();
        }

        if (state.isTraceEnabled())
        {
            auto offset = resultR.getParserState().getOffset();
            resultL.concatenateTraces(std::move(resultR)).concatenate(TraceP("L<<R, success", offset));
        }

        return resultL;
    };

    return fn;
}

/**
 * @brief Creates a parser that returns result of the second parser and ignores the
 * result of the first. If any of the parsers fails, the result will be a failure.
 *
 * @tparam L type of the value returned by the first parser
 * @tparam R type of the value returned by the second parser
 * @param l first parser (left operand)
 * @param r second parser (right operand)
 * @return Parser<R> Combined parser
 */
template<typename L, typename R>
Parser<R> operator>>(const Parser<L>& l, const Parser<R>& r)
{
    Parser<R> fn = [l, r](const ParserState& state)
    {
        auto resultL = l(state);
        if (!resultL)
        {
            if (state.isTraceEnabled())
            {
                return ResultP<R>::failure().concatenateTraces(std::move(resultL)).concatenate(
                    TraceP("L>>R, L failed", state.getOffset()));
            }
            return ResultP<R>::failure();
        }

        auto resultR = r(state);
        if (!resultR)
        {
            if (state.isTraceEnabled())
            {
                auto offset = resultL.getParserState().getOffset();
                resultR.concatenateTraces(std::move(resultL)).concatenateTraces(TraceP("L>>R, R failed", offset));
            }
            return resultR;
        }

        if (state.isTraceEnabled())
        {
            resultR.concatenateTraces(std::move(resultL))
                .concatenate(TraceP("L>>R, success", resultR.getParserState().getOffset()));
        }

        return resultR;
    };

    return fn;
}

/**
 * @brief Creates a parser that returns the result of the first parser if it succeeds,
 * or the result of the second parser if the first fails.
 *
 * @tparam T type of the value returned
 * @param l first parser (left operand)
 * @param r second parser (right operand)
 * @return  Parser<T> Combined parser
 */
template<typename T>
Parser<T> operator|(const Parser<T>& l, const Parser<T>& r)
{
    return [l, r](const ParserState& state) -> ResultP<T>
    {
        auto resultL = l(state);
        if (resultL)
        {
            if (state.isTraceEnabled())
            {
                return resultL.concatenate(TraceP("L|R, L succeeded", resultL.getParserState().getOffset()));
            }
            return resultL;
        }

        auto resultR = r(state);
        if (resultR)
        {
            if (state.isTraceEnabled())
            {
                return resultR.concatenate(std::move(resultL))
                    .concatenate(TraceP("L|R, R succeeded", resultR.getParserState().getOffset()));
            }
            return resultR;
        }

        if (state.isTraceEnabled())
        {
            return ResultP<T>::failure()
                .concatenateTraces(std::move(resultL))
                .concatenateTraces(std::move(resultR))
                .concatenate(TraceP("L|R, both failed", state.getOffset()));
        }

        return ResultP<T>::failure();
    };
}

/**
 * @brief Creates a parser that returns a tuple of the results of the two parsers. If
 * any of the parsers fails, the result will be a failure.
 *
 * @tparam L type of the value returned by the first parser
 * @tparam R type of the value returned by the second parser
 * @param l first parser (left operand)
 * @param r second parser (right operand)
 * @return Parser<std::tuple<L, R>> Combined parser
 *
 * @warning Both parsers must return a value. If you want to combine parsers that may
 * return no value, use Parser::optional() on them first.
 * @note If you want to combine one parser that never returns a value with another that returns a value, use << or >>
 * instead.
 * @see Parser::operator<<()
 * @see Parser::operator>>()
 */
template<typename L, typename R>
Parser<std::tuple<L, R>> operator&(const Parser<L>& l, const Parser<R>& r)
{
    return [l, r](const ParserState& state) -> ResultP<std::tuple<L, R>>
    {
        auto resultL = l(state);
        if (!resultL)
        {
            if (state.isTraceEnabled())
            {
                return ResultP<std::tuple<L, R>>::failure()
                    .concatenateTraces(std::move(resultL))
                    .concatenate(TraceP("L&R, L failed", state.getOffset()));
            }
            return ResultP<std::tuple<L, R>>::failure();
        }

        auto resultR = r(resultL.getParserState());
        if (!resultR)
        {
            if (state.isTraceEnabled())
            {
                auto offset = resultL.getParserState().getOffset();
                return ResultP<std::tuple<L, R>>::failure()
                    .concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenate(TraceP("L&R, R failed", offset));
            }
            return ResultP<std::tuple<L, R>>::failure();
        }

        if (!resultR.hasValue() || !resultL.hasValue())
        {
            if (state.isTraceEnabled())
            {
                std::string msg = "L&R failed";
                if (!resultL.hasValue())
                {
                    msg += ", L didn't return a value";
                }
                if (!resultR.hasValue())
                {
                    msg += ", R didn't return a value";
                }
                return ResultP<std::tuple<L, R>>::failure()
                    .concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenate(TraceP(msg, state.getOffset()));
            }
            return ResultP<std::tuple<L, R>>::failure();
        }

        if (state.isTraceEnabled())
        {
            auto offset = resultR.getParserState().getOffset();
            return ResultP<std::tuple<L, R>>::success(resultR.getState(),
                                                      std::make_tuple(resultL.popValue(), resultR.popValue()))
                .concatenateTraces(std::move(resultL))
                .concatenateTraces(std::move(resultR))
                .concatenate(TraceP("L&R, success", offset));
        }

        return ResultP<std::tuple<L, R>>::success(resultR.getState(),
                                                  std::make_tuple(resultL.popValue(), resultR.getValue()));
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
 *
 * @warning The parser must return a value. If not the result will be a failure.
 */
template<typename Tx, typename T>
Parser<Tx> fmap(std::function<Tx(T)> f, const Parser<T>& p)
{
    return [f, p](const ParserState& state) -> ResultP<Tx>
    {
        auto result = p(state);
        if (!result || !result.hasValue())
        {
            if (state.isTraceEnabled())
            {
                auto msg = std::string("fmap, failed");
                if (!result.hasValue())
                {
                    msg += ", P didn't return a value";
                }
                return ResultP<Tx>::failure().concatenateTraces(std::move(result))
                    .concatenate(TraceP(msg, state.getOffset()));
            }
            return ResultP<Tx>::failure();
        }

        if (state.isTraceEnabled())
        {
            auto offset = result.getParserState().getOffset();
            return ResultP<Tx>::success(result.getParserState(),
                                        f(result.popValue()))
                .concatenateTraces(std::move(result))
                .concatenate(TraceP("fmap, success", offset));
        }

        return ResultP<Tx>::success(result.getState(), f(result.popValue()));
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
    return [p, f](const ParserState& state) -> ResultP<Tx>
    {
        auto result = p(state);

        if (!result || !result.hasValue()
        {
            if (state.isTraceEnabled())
            {
                auto msg = std::string("P>>=M, P failed");
                if (!result.hasValue())
                {
                    msg += ", didn't return a value";
                }
                return ResultP<Tx>::failure()
                    .concatenateTraces(std::move(result))
                    .concatenate(TraceP(msg, state.getOffset()));
            }
            return ResultP<Tx>::failure();
        }

        auto newParser = f(result.popValue());
        auto newResult = newParser(state);

        if(state.isTraceEnabled())
        {
            auto trace = newResult ? "P>>=M, success" : "P>>=M, M failed";
            auto offset = newResult ? newResult.getParserState().getOffset() : state.getOffset();
            return newResult.concatenateTrace(std::move(result)).concatenate(TraceP(std::move(trace), offset));
        }
        return newResult;
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
    return [p](const ParserState& state) -> ResultP<Values<T>>
    {
        Values<T> values {};

        const lasState = state;
        auto result = p(lasState);

        while (result)
        {
            if (result.hasValue())
            {
                values.push_back(result.popValue());
            }
            lasState = result.getParserState();
            result = p(lasState).concatenateTrace(std::move(result));
        }

        if (state.isTraceEnabled())
        {
            auto offset = lasState.getOffset();
            return ResultP<Values<T>>::success(lasState,
                                               std::move(values))
                .concatenateTraces(std::move(result))
                .concatenate(TraceP("MANY(P), success", offset));
        }

        return ResultP<Values<T>>::success(lasState, std::move(values));
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
    return [manyP, p](const ParserState& state) -> ResultP<Values<T>>
    {
        auto firstRes = p(state);
        if (!firstRes)
        {
            if (state.isTraceEnabled())
            {
                return ResultP<Values<T>>::failure()
                    .concatenateTraces(std::move(firstRes))
                    .concatenate(TraceP("MANY1(P), failed", state.getOffset()));
            }
            return ResultP<Values<T>>::failure();
        }

        Values<T> values {};
        if (firstRes.hasValue())
        {
            values.push_back(firstRes.popValue());
        }

        auto manyRes = manyP(firstRes.getParserState());
        if (manyRes && manyRes.hasValue())
        {
            values.splice(values.end(), manyRes.popValue());
        }

        if (state.isTraceEnabled())
        {
            auto offset = manyRes.getParserState().getOffset();
            return ResultP<Values<T>>::success(manyRes.getParserState(),
                                               std::move(values))
                .concatenateTraces(std::move(firstRes))
                .concatenateTraces(std::move(manyRes))
                .concatenate(TraceP("MANY1(P), success", offset));
        }

        return ResultP<Values<T>>::success(manyRes.getParserState(), std::move(values));

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

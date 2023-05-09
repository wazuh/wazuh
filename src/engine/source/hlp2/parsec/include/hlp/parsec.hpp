#ifndef _PARSEC_HPP_
#define _PARSEC_HPP_

#include <deque>
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
        if (m_pos > m_data.size())
        {
            throw std::runtime_error(fmt::format("ParserState::advance: The position '{}' is greater than the maximum "
                                                 "position '{}' for the input: '{}'",
                                                 m_pos,
                                                 m_data.size(),
                                                 m_data));
        }
        return *this;
    }

    /**
     * @brief Advance the current position in the data, pointing to the next character to be parsed, returning a copy
     * of the input with the new position
     *
     * @param offset The offset to advance the current position in the data
     * @return ParserState A copy of the input with the new position
     */
     [[nodiscard]] ParserState advance(std::size_t offset) const
    {
        ParserState copy(*this);
        copy.advance(offset);
        return copy;
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
    std::size_t getRemainingSize() const { return m_data.size() - m_pos; }

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
    std::string m_message;      ///< The message of the trace (usually the name of the parser and message of the trace)
    std::size_t m_offset;       ///< The offset where the parser generated the trace
    std::size_t m_order;        ///< The order in which the trace was created

    static std::size_t s_order; ///< A static variable to keep track of the order of created instances

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
        , m_order(s_order++)
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
        , m_order(s_order++)
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

    /**
     * @brief Get the order of the TraceP object
     *
     * @return std::size_t The order of the TraceP object
     */
    std::size_t getOrder() const { return m_order; }
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
    ParserState m_parserState; ///< The parser state
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
     * @brief Construct a ResultP successful result with a value and no traces
     *
     * @param state The state of parser
     * @param value The value of the result
     */
    ResultP(const ParserState& state, T&& value)
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
    ResultP(const ParserState& state, T&& value, TraceP&& trace)
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
    ResultP(const ParserState& state, T&& value, std::list<TraceP>&& traces)
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
    ResultP(const ParserState& state)
        : m_value(std::nullopt)
        , m_traces()
        , m_parserState(state)
    {
    }

    /**
     * @brief Construct a ResultP failure result with a trace
     *
     * @param trace
     */
    ResultP(const ParserState& state, TraceP&& trace)
        : m_value()
        , m_traces({std::move(trace)})
        , m_parserState(state)
    {
    }

    /**
     * @brief Construct a ResultP failure result with a list of traces
     *
     * @param traces
     */
    ResultP(const ParserState& state, std::list<TraceP>&& traces)
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
     * @brief Check if the result is successful (has a value)
     *
     * @return true if the result is successful, false otherwise
     */
    bool isSuccessful() const { return m_value.has_value(); }

    /**
     * @brief Check if the result is failure (has no value)
     *
     * @return true if the result is failure, false otherwise
     */
     bool isFailure() const { return !isSuccessful(); }

    /**
     * @brief Operator bool, check if the result is successful (has a value)
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
    const ParserState& getParserState() const { return m_parserState; }

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

    const std::list<TraceP>& getTraces() const
    {
        if (!m_traces.has_value())
        {
            throw std::runtime_error("ResultP::getTraces() called on a result with no traces");
        }
        return m_traces.value();
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

    /**
     * @brief Concatenate a new trace with the traces of the result with a current offset of the parser
     *
     */
    ResultP& concatenateTraces(const std::string& message)
    {
        return concatenateTraces(TraceP(message, m_parserState.getOffset()));
    }

    /**************************************************************************
     * Operations of value
     **************************************************************************/
    /**
     * @brief Pop the value of the result. The result must have a value (be successful)
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

    const T& getValue () const
    {
        if (!m_value.has_value())
        {
            throw std::runtime_error("ResultP::getValue() called on a result with no value");
        }
        return m_value.value();
    }

    /**
     * @brief Set the result as successful with no value
     *
     * @param state The parser state after the parsing
     * @return ResultP& A reference to the result
     */
    ResultP& setSuccess(const ParserState& state, T&& value)
    {
        m_parserState = state;
        m_value = std::move(value);
        return *this;
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
    static ResultP<T> success(const ParserState& state) { return ResultP<T>(state, T()); }

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
    static ResultP<T> failure(const ParserState& state) { return ResultP<T>(state); }

    /**
     * @brief Create a failed result with a trace
     *
     * @param trace The trace
     * @return ResultP<T> The failed result with a trace
     */
    static ResultP<T> failure(const ParserState& state, TraceP&& trace) { return ResultP<T>(state, std::move(trace)); }

    /**
     * @brief Create a failed result with a list of traces
     *
     * @param traces The list of traces
     * @return ResultP<T> The failed result with a list of traces
     */
    static ResultP<T> failure(const ParserState& state, std::list<TraceP>&& traces)
    {
        return ResultP<T>(state, std::move(traces));
    }
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
 * @param p The parser to make optional
 * @return Parser<T> Combined parser
 */
template<typename T>
Parser<T> opt(const Parser<T>& p)
{
    return [=](const ParserState& state) -> ResultP<T>
    {
        {
            ResultP<T> retResult = p(state);
            bool isSuccess = retResult.isSuccessful();

            if (!isSuccess)
            {
                retResult.setSuccess(state, T());
            }

            if (state.isTraceEnabled())
            {
                std::string traceMsg = isSuccess ? "[success] [opt(P)] P succeeded" : "[success] [opt(P)] P failed";
                retResult.concatenateTraces(traceMsg);
            }

            return retResult;
        };
    };
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
    return [l, r](const ParserState& state) -> ResultP<L>
    {
        auto retResult = ResultP<L>::failure(state);

        auto resultL = l(state);
        if (resultL.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL));
                retResult.concatenateTraces("[failure] [L<<R] L failed");
            }
            return retResult;
        }

        auto resultR = r(resultL.getParserState());
        if (resultR.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenateTraces("[failure] [L<<R] R failed");
            }
            return retResult;
        }

        // Success
        retResult.setSuccess(resultR.getParserState(), resultL.popValue());

        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resultL))
                .concatenateTraces(std::move(resultR))
                .concatenateTraces("[success] [L<<R] L succeeded");
        }

        return retResult;
    };
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
    return [l, r](const ParserState& state) -> ResultP<R>
    {
        auto retResult = ResultP<R>::failure(state);

        auto resultL = l(state);
        if (resultL.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL));
                retResult.concatenateTraces("[failure] [L>>R] L failed");
            }
            return retResult;
        }

        auto resultR = r(resultL.getParserState());
        if (resultR.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenateTraces("[failure] [L>>R] R failed");
            }
            return retResult;
        }

        // Success
        retResult.setSuccess(resultR.getParserState(), resultR.popValue());

        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resultL))
                .concatenateTraces(std::move(resultR))
                .concatenateTraces("[success] [L>>R] L succeeded");
        }
        return retResult;
    };
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
        auto retResult = ResultP<T>::failure(state);

        auto resultL = l(state);
        if (resultL.isSuccessful())
        {
            // Success
            retResult.setSuccess(resultL.getParserState(), resultL.popValue());

            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL)).concatenateTraces("[success] [L|R] L succeeded");
            }
            return retResult;
        }

        auto resultR = r(state);
        if (resultR.isSuccessful())
        {
            // Success
            retResult.setSuccess(resultR.getParserState(), resultR.popValue());

            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenateTraces("[success] [L|R] R succeeded");
            }
            return retResult;
        }

        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resultL))
                .concatenateTraces(std::move(resultR))
                .concatenateTraces("[failure] [L|R] L and R failed");
        }

        return retResult;
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
        auto retResult = ResultP<std::tuple<L, R>>::failure(state);
        auto resultL = l(state);
        if (resultL.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL)).concatenateTraces("[failure] [L&R] L failed");
            }
            return retResult;
        }

        auto resultR = r(resultL.getParserState());
        if (resultR.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(resultL))
                    .concatenateTraces(std::move(resultR))
                    .concatenateTraces("[failure] [L&R] R failed");
            }
            return retResult;
        }

        // Success
        retResult.setSuccess(resultR.getParserState(), std::make_tuple(resultL.popValue(), resultR.popValue()));

        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resultL))
                .concatenateTraces(std::move(resultR))
                .concatenateTraces("[success] [L&R] L and R succeeded");
        }

        return retResult;
    };
}

/**
 * @brief Mergeable is a struct that contains a semantic processor and a result of the sintactic parser
 *
 * @details The semantic processor is a function that takes a T& and a list of tokens and process the tokens
 * The function returns a tuple with a boolean that indicates if the process was successful
 * and an optional TraceP that contains the error message if the process was not successful
 * The result is the result of the semantic processor, it is a T and can be merged with other Mergeable
 *
 * @tparam T The type of the result of the semantic processor
 */
template<typename T>
struct Mergeable
{
    /**
     * @brief This is a function that takes a T& and a list of tokens and process the tokens
     * @details The function returns a tuple with a boolean that indicates if the process was successful
     * and an optional TraceP that contains the error message if the process was not successful
     */
    std::function<std::tuple<bool, std::optional<TraceP>>(T&, const std::deque<std::string_view>&, const ParserState&)>
        m_semanticProcessor;
    T m_result;                            ///< The result of the semantic processor
    std::deque<std::string_view> m_tokens; ///< Store the tokens of the result the sintactic parser found
    std::optional<std::function<void(T& dst, T& src)>> m_mergeFunction; ///< The function that merges two Mergeable
};

/**
 * @brief This is a parser that returns a Mergeable that contains a semantic processor and a result of the sintactic
 * parser
 *
 * @tparam T The type of the result of the semantic processor
 */
template<typename T>
using MergeableParser = Parser<Mergeable<T>>; // This is a parser that returns a Mergeable

/**
 * @brief This is a result of a MergeableParser that contains a Mergeable that contains a semantic processor and a
 * result of the sintactic parser
 *
 * @tparam T The type of the result of the semantic processor
 */
template<typename T>
using MergeableResultP = ResultP<Mergeable<T>>; // This is a result of a MergeableParser

/**
 * @brief This is a function that takes a list of MergeableParser and returns a parser that executes all the parsers in
 * the list as a sequence
 *
 * @details The function returns a parser that executes all the parsers in the list as a sequence, each parser has a
 * sintactic parser and a semantic processor. The sintactic parser is executed in the order of the list, if one of the
 * sintactic parser fails, the function returns a failure. If all the sintactic parser succeeds, the semantic processor
 * of each parser is executed in the order of the list. If one of the semantic processor fails, the function returns a
 * failure.
 *
 * @tparam T The type of the result of the semantic processor
 * @param parsers The list of MergeableParser
 * @return Parser<T> A parser that executes all the parsers in the list as a sequence
 */
template<typename T>
Parser<T> merge(const std::list<MergeableParser<T>>& parsers)
{
    return [parsers](const ParserState& state) -> ResultP<T>
    {
        auto retResult = ResultP<T>::failure(state);
        std::list<Mergeable<T>> mergeables;
        auto currentState = state;

        /************************************************
                    Sintactic parser stage
        ************************************************/
        {
            for (auto& parser : parsers)
            {
                auto result = parser(currentState);
                if (result.isFailure())
                {
                    if (state.isTraceEnabled())
                    {
                        retResult.concatenateTraces(std::move(result))
                            .concatenateTraces("[failure] [merge] Sintactic fail");
                    }
                    return retResult;
                }

                mergeables.push_back(result.popValue());        // Store the result of the sintactic parser
                currentState = result.getParserState();         // Update the current state
                retResult.concatenateTraces(std::move(result)); // Concatenate the traces if the state is enabled
            }

            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces("[success] [merge] Sintactic success");
            }
        }

        /************************************************
                    Semantic processor stage
        ************************************************/
        {
            auto finalResult = T();
            for (auto& mergeable : mergeables)
            {
                auto [success, optTrace] = mergeable.m_semanticProcessor(finalResult, mergeable.m_tokens, state);

                if (optTrace.has_value())
                {
                    retResult.concatenateTraces(std::move(*optTrace));
                }

                if (!success)
                {
                    if (state.isTraceEnabled())
                    {
                        retResult.concatenateTraces("[failure] [merge] Semantic fail");
                    }
                    return retResult;
                }

                if (mergeable.m_mergeFunction.has_value())
                {
                    (*mergeable.m_mergeFunction)(finalResult, mergeable.m_result);
                }
            }

            retResult.setSuccess(currentState, std::move(finalResult));

            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces("[success] [merge] Semantic success");
            }
        }
        return retResult;
    };
}


template<typename T>
MergeableParser<T> andMergeable(const MergeableParser<T>& l, const MergeableParser<T>& r)
{
    return [l, r](const ParserState& state) -> MergeableResultP<T> {

        auto result = MergeableResultP<T>::failure(state);

        /***********************
        * Sintactic parser stage
        ************************/
        auto lResult = l(state);
        if (lResult.isFailure())
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces(std::move(lResult))
                    .concatenateTraces("[failure] [mergebleAnd] Left parser fail");
            }
            return result;
        }

        auto rResult = r(lResult.getParserState());
        if (rResult.isFailure())
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces(std::move(lResult))
                    .concatenateTraces(std::move(rResult))
                    .concatenateTraces("[failure] [mergebleAnd] Right parser fail");
            }
            return result;
        }

        // Candidate of state
        auto candidateState = rResult.getParserState();

        /***********************
         * Semantic processor stage
         * **********************/
        auto lMerable {lResult.popValue()};
        auto rMerable {rResult.popValue()};

        // Concatenate the traces if the state is enabled
        if (state.isTraceEnabled())
        {
            result.concatenateTraces(std::move(lResult))
                .concatenateTraces(std::move(rResult))
                .concatenateTraces("[success] [mergebleAnd] Sintactic success");
        }

        // Value of the result
        Mergeable<T> valueResult;
        valueResult.m_tokens = {};

        // Merge the results of the sintactic parsers if the merge function is defined
        valueResult.m_result = {};
        if (lMerable.m_mergeFunction.has_value())
        {
            (*lMerable.m_mergeFunction)(valueResult.m_result, lMerable.m_result);
            valueResult.m_mergeFunction = lMerable.m_mergeFunction;
        }
        if (rMerable.m_mergeFunction.has_value())
        {
            (*rMerable.m_mergeFunction)(valueResult.m_result, rMerable.m_result);
            if (!valueResult.m_mergeFunction.has_value())
            {
                valueResult.m_mergeFunction = rMerable.m_mergeFunction;
            }
        }

        // Define the semantic processor
        valueResult.m_semanticProcessor = [lMerable, rMerable](T& finalResult, const std::deque<std::string_view>& tokens, const ParserState& state) -> std::tuple<bool, std::optional<TraceP>>
        {
            auto lResult = lMerable.m_semanticProcessor(finalResult, lMerable.m_tokens, state);
            if (!std::get<0>(lResult))
            {
                return lResult;
            }

            auto rResult = rMerable.m_semanticProcessor(finalResult, rMerable.m_tokens, state);
            if (!std::get<0>(rResult))
            {
                return rResult;
            }

            return {true, {}}; // Success
        };

        result.setSuccess(candidateState, std::move(valueResult));
        return result;
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
        auto retResult = ResultP<Tx>::failure(state);
        auto result = p(state);

        if (result.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(result)).concatenateTraces("[failure] [fmap(P)] P failure");
            }
            return retResult;
        }

        retResult.setSuccess(result.getParserState(), f(result.popValue()));
        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(result)).concatenateTraces("[success] [fmap(P)] P success");
        }

        return retResult;
    };
}

/* Monadic binding helper type */
template<typename Tx, typename T>
using M = std::function<Parser<Tx>(T)>;

/**
 * @brief Creates a parser that creates a new parser from the result of the given
 * parser using the factory function f. If the given parser fails, the result will be
 * a failure. If was successful, the result of the factory function will be executed with the result of the given
 * parser.
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
        auto retResult = ResultP<Tx>::failure(state);
        auto pResult = p(state);


        if (pResult.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(pResult)).concatenateTraces("[failure] [P>>=M] P failure");
            }
            return retResult;
        }

        auto newParser = f(pResult.popValue());
        auto newResult = newParser(pResult.getParserState());

        if (newResult.isSuccessful())
        {
            retResult.setSuccess(newResult.getParserState(), newResult.popValue());
        }

        if (state.isTraceEnabled())
        {
            auto trace = newResult ? "[success] [P>>=M] P success" : "[failure] [P>>=M] M failed";
            auto offset = newResult ? newResult.getParserState().getOffset() : pResult.getParserState().getOffset();

            retResult.concatenateTraces(std::move(pResult))
                .concatenateTraces(std::move(newResult))
                .concatenateTraces(TraceP{trace, offset});
        }
        return retResult;
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

        auto lasState = state;
        auto result = p(lasState);

        while (result.isSuccessful())
        {
            values.push_back(result.popValue());
            lasState = result.getParserState();
            result = p(lasState).concatenateTraces(std::move(result));
        }

        auto retResult = ResultP<Values<T>>::success(lasState, std::move(values));
        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(result)).concatenateTraces("[success] [many] Success");
        }

        return retResult;
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
        auto retResult = ResultP<Values<T>>::failure(state);
        Values<T> values {};

        auto firstRes = p(state);
        if (firstRes.isFailure())
        {
            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(firstRes)).concatenateTraces("[failure] [many1(P)] P failure");
            }
            return retResult;
        }

        values.push_back(firstRes.popValue());

        auto manyRes = manyP(firstRes.getParserState());

        // Always succeeds
        values.splice(values.end(), manyRes.popValue());
        retResult.setSuccess(manyRes.getParserState(), std::move(values));

        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(firstRes))
                .concatenateTraces(std::move(manyRes))
                .concatenateTraces("[success] [many1(P)] Success");
        }

        return retResult;
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

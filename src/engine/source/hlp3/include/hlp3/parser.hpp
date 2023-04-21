#ifndef _HLP3_PARSER_HPP
#define _HLP3_PARSER_HPP

#include <functional>
#include <list>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

namespace hlp3::parser
{

// Input for parser
class InputP final
{

private:
    std::string_view m_data;
    std::size_t m_pos;

public:
    // TODO Capture this
    InputP() {
        throw std::logic_error("Input::Input: default constructor is not allowed");
    }

    InputP(std::string_view data)
        : m_data(data)
        , m_pos(0) {};

    void addOffset(std::size_t offset)
    {
        m_pos += offset;
        if (m_pos > m_data.size())
        {
            throw std::logic_error("Input::addOffset: offset is too large");
        }
    }

    std::size_t getPos() const { return m_pos; }

    std::size_t getRemaining() const { return m_data.size() - m_pos; }

    std::string_view getRemainingData() const { return m_data.substr(m_pos); }
};

// Parser Tracer
class TraceP
{
private:
    std::string m_message;
    std::size_t m_offset;

public:
    TraceP(std::string message, std::size_t offset)
        : m_message(message)
        , m_offset(offset)
    {
    }

    std::string getMessage() const { return m_message; }
    std::size_t getOffset() const { return m_offset; }
};

// Parser Return
template<typename T>
class ResultP final
{
private:
    // Si cambio algo aca revisar los constructores de copia y movimiento
    std::optional<T> m_value; // The value of the result (can be empty if the result is successful and can have a
                              // parcial result if the result is not successful)
    std::optional<std::list<TraceP>>
        m_traces; // The trace of the result, can be empty, independent of the result being successful or not
    std::optional<InputP> m_remmaining; // The remaining input if the result is successful, empty otherwise

public:
    /**************************************************************************
     * Success Constructors
     *
     * The result is successful m_remmaining is set to the remaining input
     * m_value is optional and can be empty no all parsers need to return a value
     * m_traces is optional and can be empty or have multiple entries if the parser was a chain of parsers
     *
     **************************************************************************/
    // Used for parsers that do not return a value and are successful
    ResultP(InputP remmaining)
        : m_value()
        , m_traces()
        , m_remmaining(remmaining)
    {
    }

    ResultP(InputP remmaining, T&& value)
        : m_value(std::move(value))
        , m_traces()
        , m_remmaining(remmaining)
    {
    }

    ResultP(InputP remmaining, T&& value, TraceP&& trace)
        : m_value(std::move(value))
        , m_traces({std::move(trace)})
        , m_remmaining(remmaining)
    {
    }

    ResultP(InputP remmaining, T&& value, std::list<TraceP>&& traces)
        : m_value(std::move(value))
        , m_traces(std::move(traces))
        , m_remmaining(remmaining)
    {
    }

    /**************************************************************************
     * Failure Constructors
     **************************************************************************/
    // Used for parsers that do not return a value and are not successful
    ResultP()
        : m_value()
        , m_traces()
        , m_remmaining()
    {
    }

    ResultP(TraceP&& trace)
        : m_value()
        , m_traces({std::move(trace)})
        , m_remmaining()
    {
    }

    ResultP(std::list<TraceP>&& traces)
        : m_value()
        , m_traces(std::move(traces))
        , m_remmaining()
    {
    }

    ResultP(T&& value)
        : m_value(std::move(value))
        , m_traces()
        , m_remmaining()
    {
    }

    ResultP(T&& value, TraceP&& trace)
        : m_value(std::move(value))
        , m_traces({std::move(trace)})
        , m_remmaining()
    {
    }

    ResultP(T&& value, std::list<TraceP>&& traces)
        : m_value(std::move(value))
        , m_traces(std::move(traces))
        , m_remmaining()
    {
    }

    /**************************************************************************
     * Move Constructors
     **************************************************************************/
    ResultP(ResultP&& other)
        : m_value(std::move(other.m_value))
        , m_traces(std::move(other.m_traces))
        , m_remmaining(std::move(other.m_remmaining))
    {
    }

    // Move assignment operator
    ResultP& operator=(ResultP&& other)
    {
        m_value = std::move(other.m_value);
        m_traces = std::move(other.m_traces);
        m_remmaining = std::move(other.m_remmaining);
        return *this;
    }

    /**************************************************************************
     * Copy Constructors
     **************************************************************************/
    ResultP(const ResultP& other)
        : m_value(other.m_value)
        , m_traces(other.m_traces)
        , m_remmaining(other.m_remmaining)
    {
    }

    // Copy assignment operator
    ResultP& operator=(const ResultP& other)
    {
        m_value = other.m_value;
        m_traces = other.m_traces;
        m_remmaining = other.m_remmaining;
        return *this;
    }

    /**************************************************************************
     *  Results and operators
     **************************************************************************/
    bool isSuccessful() const { return m_remmaining.has_value(); }
    operator bool() const { return isSuccessful(); }

    // return remaining input
    InputP getRemaining() const {
        if (m_remmaining.has_value())
        {
            return m_remmaining.value();
        }
        return InputP();
    }

    // Concatenate 2 traces
    template<typename U>
    ResultP& concatenateTraces(ResultP<U>&& other)
    {
        auto otherTraces = other.popTraces();
        if (otherTraces.has_value())
        {
            if (m_traces.has_value())
            {
                m_traces.value().splice(m_traces.value().end(), otherTraces.value());
            }
            else
            {
                m_traces = std::move(otherTraces);
            }
        }
        return *this;
    }

    /**************************************************************************
     * Getters
     **************************************************************************/
    /* traces */
    bool hasTraces() const { return m_traces.has_value(); }
    std::optional<std::list<TraceP>> popTraces()
    {
        auto traces = std::move(m_traces);
        m_traces = std::nullopt;
        return traces;
    }

    /* Value */
    bool hasValue() const { return m_value.has_value(); }
    std::optional<T> popValue()
    {
        auto value = std::move(m_value);
        m_value = std::nullopt;
        return value;
    }

    /**************************************************************************
     * Static methods
     **************************************************************************/
    static ResultP<T> success(const InputP& remmaining) { return ResultP<T>(remmaining); }

    static ResultP<T> success(const InputP& remmaining, T&& value) { return ResultP<T>(remmaining, std::move(value)); }

    static ResultP<T> success(const InputP& remmaining, T&& value, TraceP&& trace)
    {
        return ResultP<T>(remmaining, std::move(value), std::move(trace));
    }

    static ResultP<T> success(const InputP& remmaining, T&& value, std::list<TraceP>&& traces)
    {
        return ResultP<T>(remmaining, std::move(value), std::move(traces));
    }

    static ResultP<T> failure() { return ResultP<T>(); }

    static ResultP<T> failure(TraceP&& trace) { return ResultP<T>(std::move(trace)); }

    static ResultP<T> failure(std::list<TraceP>&& traces) { return ResultP<T>(std::move(traces)); }

    static ResultP<T> failure(T&& value) { return ResultP<T>(std::move(value)); }
};

// Parser
template<typename T>
using Parser = std::function<ResultP<T>(InputP)>;

} // namespace hlp3::parser

#endif // _HLP3_PARSER_HPP

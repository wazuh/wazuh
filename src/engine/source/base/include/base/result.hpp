#ifndef _RESULT_H
#define _RESULT_H

#include <optional>
#include <string>

namespace base::result
{

/**
 * @brief Wraps an event payload together with a trace message and success/failure status.
 *
 * @tparam Event The type of the payload.
 */
template<typename Event>
class Result
{
private:
    inline static const std::string EMPTY_TRACE {}; ///< Shared empty string for cases where no trace is present

    Event m_payload;                    ///< The event payload
    std::optional<std::string> m_trace; ///< Optional trace message
    bool m_success;                     ///< Status of the result, true for success, false for failure

public:
    /**
     * @brief Construct a new Result object without parameters.
     *
     */
    Result() {}

    /**
     * @brief Construct a new Result object with payload and status only (no trace).
     *
     * @param payload Event.
     * @param success Status of the event.
     */
    Result(Event payload, bool success)
        : m_payload {std::move(payload)}
        , m_trace {std::nullopt}
        , m_success {success}
    {
    }

    /**
     * @brief Construct a new Result object with parameters.
     *
     * @param payload Event.
     * @param trace Tracer object.
     * @param success Status of the event.
     */
    Result(Event payload, std::string trace, bool success)
        : m_payload {std::move(payload)}
        , m_trace {std::move(trace)}
        , m_success {success}
    {
    }

    Result(const Result&) = default;
    Result(Result&&) = default;
    ~Result() = default;
    Result& operator=(const Result&) = default;
    Result& operator=(Result&&) = default;

    /**
     * @brief Check if the result is a success.
     *
     * @return true if the result has been a success.
     * @return false if the result has been a failure.
     */
    operator bool() const { return m_success; }

    /**
     * @brief Check if the result is a success.
     *
     * @return true if the result has been a success.
     * @return false otherwise.
     */
    bool success() const { return m_success; }

    /**
     * @brief Check if the result is a failure.
     *
     * @return true if the result has been a failure.
     * @return false otherwise.
     */
    bool failure() const { return !m_success; }

    /**
     * @brief Returns the event payload.
     *
     * @return const Event& the event payload.
     */
    const Event& payload() const { return m_payload; }

    /**
     * @brief Check if the result has a trace.
     *
     * @return true if a trace is present.
     */
    bool hasTrace() const { return m_trace.has_value(); }

    /**
     * @brief Returns the event trace. If no trace is present, returns a reference to a
     * shared empty string.
     *
     * @return const std::string& the event trace.
     */
    const std::string& trace() const { return m_trace.has_value() ? m_trace.value() : EMPTY_TRACE; }

    /**
     * @brief Moves and returns the trace string. If no trace is present, returns an empty string.
     *
     * @return std::string the event trace.
     */
    std::string popTrace()
    {
        if (m_trace.has_value())
        {
            std::string t = std::move(m_trace.value());
            m_trace.reset();
            return t;
        }
        return {};
    }

    /**
     * @brief Get the payload object.
     *
     * @return Event the payload object.
     */
    Event popPayload() { return std::move(m_payload); }

    /**
     * @brief Set the status object.
     *
     * @param success the status object.
     */
    void setStatus(bool success) { m_success = success; }

    /**
     * @brief Set the trace object.
     *
     * @param trace the trace object.
     */
    void setTrace(std::string trace) { m_trace = std::move(trace); }

    /**
     * @brief Set the payload object.
     *
     * @param payload th payload object.
     */
    void setPayload(Event&& payload) { m_payload = std::move(payload); }
};

/**
 * @brief Creates a success Result without trace.
 */
template<typename Event>
Result<Event> makeSuccess(Event payload)
{
    return Result<Event> {std::move(payload), true};
}

/**
 * @brief Creates a success Result with trace.
 */
template<typename Event>
Result<Event> makeSuccess(Event payload, std::string trace)
{
    return Result<Event> {std::move(payload), std::move(trace), true};
}

/**
 * @brief Creates a failure Result without trace.
 */
template<typename Event>
Result<Event> makeFailure(Event payload)
{
    return Result<Event> {std::move(payload), false};
}

/**
 * @brief Creates a failure Result with trace.
 */
template<typename Event>
Result<Event> makeFailure(Event payload, std::string trace)
{
    return Result<Event> {std::move(payload), std::move(trace), false};
}

} // namespace base::result

#endif // _RESULT_H

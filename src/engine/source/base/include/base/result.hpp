#ifndef _RESULT_H
#define _RESULT_H

#include <string>

namespace base::result
{

template<typename Event>
class Result
{
private:
    Event m_payload;
    std::string m_trace;
    bool m_success;

public:
    /**
     * @brief Construct a new Result object without parameters.
     *
     */
    Result() {}

    /**
     * @brief Construct a new Result object with parameters.
     *
     * @param payload Event.
     * @param trace Tracer object.
     * @param success Status of the event.
     */
    Result(Event payload, std::string trace, bool success)
        : m_payload {payload}
        , m_trace {trace}
        , m_success {success}
    {
    }

    /**
     * @brief Copy constructs a new Result object.
     *
     * @param other The Result to copy.
     */
    Result(const Result& other)
        : m_payload {other.m_payload}
        , m_trace {other.m_trace}
        , m_success {other.m_success}
    {
    }

    /**
     * @brief Move copy constructor.
     *
     * @param other The Result to copy.
     */
    Result(Result&& other)
        : m_payload {std::move(other.m_payload)}
        , m_trace {other.m_trace}
        , m_success {other.m_success}
    {
    }

    /**
     * @brief Destroy the Result object
     */
    ~Result() = default;

    /**
     * @brief Copy assignment operator.
     *
     * @param other The Result to copy.
     * @return Result& The new Result object.
     */
    Result& operator=(const Result& other)
    {
        m_payload = other.m_payload;
        m_trace = other.m_trace;
        m_success = other.m_success;
        return *this;
    }

    /**
     * @brief Move copy assignment operator.
     *
     * @param other The Result to move.
     * @return Result& The new Result object.
     */
    Result& operator=(Result&& other)
    {
        m_payload = std::move(other.m_payload);
        m_trace = other.m_trace;
        m_success = other.m_success;
        return *this;
    }

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
     * @brief Returns the event trace.
     *
     * @return std::string the event trace.
     */
    std::string trace() const { return m_trace; }

    /**
     * @brief Returns the event trace.
     *
     * @return std::string the event trace.
     */
    std::string popTrace() const { return std::move(m_trace); }

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
    void setTrace(std::string trace) { m_trace = trace; }

    /**
     * @brief Set the payload object.
     *
     * @param payload th payload object.
     */
    void setPayload(Event&& payload) { m_payload = std::move(payload); }
};

/**
 * @brief Returns the result of the event with all the information that it has been
 * success.
 * Incorporates the trace and sets m_success to true
 *
 * @tparam Event
 * @param payload event message
 * @param trace trace to be filled
 * @return Result<Event> Result of the event with all the complete information.
 */
template<typename Event>
Result<Event> makeSuccess(Event payload, std::string trace = "")
{
    return Result<Event> {payload, trace, true};
}

/**
 * @brief Returns the result of the event with all the information that it has been
 * failure.
 * Incorporates the trace and sets m_success to false
 *
 * @tparam Event
 * @param payload event message
 * @param trace trace to be filled
 * @return Result<Event> Result of the event with all the complete information.
 */
template<typename Event>
Result<Event> makeFailure(Event payload, std::string trace = "")
{
    return Result<Event> {payload, trace, false};
}

} // namespace base::result

#endif // _RESULT_H

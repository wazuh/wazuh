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
    Result(Event payload, std::string trace, bool success)
        : m_payload {payload}
        , m_trace {trace}
        , m_success {success}
    {
    }

    Result(const Result& other)
        : m_payload {other.m_payload}
        , m_trace {other.m_trace}
        , m_success {other.m_success}
    {
    }

    Result(Result&& other)
        : m_payload {std::move(other.m_payload)}
        , m_trace {other.m_trace}
        , m_success {other.m_success}
    {
    }

    Result& operator=(const Result& other)
    {
        m_payload = other.m_payload;
        m_trace = other.m_trace;
        m_success = other.m_success;
        return *this;
    }
/*
    Result& operator=(Result&& other)
    {
        m_payload = std::move(other.m_payload);
        m_trace = other.m_trace;
        m_success = other.m_success;
        return *this;
    }
*/
    operator bool() const
    {
        return m_success;
    }

    bool success() const
    {
        return m_success;
    }

    bool failure() const
    {
        return !m_success;
    }

    const Event& payload() const
    {
        return m_payload;
    }

    std::string trace() const
    {
        return m_trace;
    }

    Event popPayload()
    {
        return std::move(m_payload);
    }

    void setStatus(bool success)
    {
        m_success = success;
    }

    void setTrace(std::string trace)
    {
        m_trace = trace;
    }

    void setPayload(Event&& payload)
    {
        m_payload = std::move(payload);
    }
};

template<typename Event>
Result<Event> makeSuccess(Event payload, std::string trace = "")
{
    return Result<Event> {payload, trace, true};
}

template<typename Event>
Result<Event> makeFailure(Event payload, std::string trace = "")
{
    return Result<Event> {payload, trace, false};
}

} // namespace base::result

#endif // _RESULT_H

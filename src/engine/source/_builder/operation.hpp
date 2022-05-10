#ifndef _OPERATION_H
#define _OPERATION_H

#include <functional>
#include <string>

#include <_builder/event.hpp>
#include <_builder/json.hpp>

template<typename Event>
class Result
{
private:
    Event m_event;
    std::string_view m_trace;
    bool m_success;

public:
    Result(Event&& event, std::string_view trace, bool&& success) noexcept
        : m_event {std::move(event)}
        , m_trace {trace}
        , m_success {std::move(success)}
    {
    }

    operator bool() const
    {
        return m_success;
    }

    Result(Result&& other) noexcept
        : m_event {std::move(other.m_event)}
        , m_trace {other.m_trace}
        , m_success {std::move(other.m_success)}
    {
    }

    Result& operator=(Result&& other) noexcept
    {
        m_event = std::move(other.m_event);
        m_trace = other.m_trace;
        m_success = std::move(other.m_success);
        return *this;
    }

    const Event& event() const
    {
        return m_event;
    }

    Event popEvent()
    {
        return std::move(m_event);
    }

    std::string_view getTrace()
    {
        return m_trace;
    }

    bool success() const
    {
        return m_success;
    }

    bool failure() const
    {
        return !m_success;
    }
};

template<typename Event>
Result<Event> makeSuccess(Event&& event, std::string_view trace)
{
    return Result {std::move(event), trace, true};
}

template<typename Event>
Result<Event> makeFailure(Event&& event, std::string_view trace)
{
    return Result {std::move(event), trace, false};
}

using Operation = std::function<Result<Event<Json>>(Event<Json>)>;

#endif // _OPERATION_H

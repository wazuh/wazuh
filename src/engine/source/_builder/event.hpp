#ifndef _EVENT_H
#define _EVENT_H

template<typename Payload>
class Event
{
private:
    Payload m_payload;

public:
    // Build event from payload, steals it.
    Event(Payload&& payload) noexcept
        : m_payload {std::move(payload)}
    {
    }

    // If we want payload from a temporal object, transfer ownership.
    Payload&& payload() && noexcept
    {
        return std::move(m_payload);
    }

    // If we want payload from an lvalue, pass it by const reference
    const Payload& payload() const & noexcept
    {
        return m_payload;
    }

    Payload& payload() & noexcept
    {
        return m_payload;
    }

    void updatePayload(std::function<void(Payload&)>& updater)
    {
        updater(m_payload);
    }

    // Payload extraction
    Payload&& getPayload() noexcept
    {
        return std::move(m_payload);
    }

    // Forcing move semantics
    Event() = delete; // This ensures a given event is always created with payload, i.e valid state for noexcept shakes.
    Event(const Event& other) = delete;
    Event& operator=(const Event& other) = delete;

    Event(Event&& other) noexcept
        : m_payload {std::move(other.m_payload)}
    {
    }

    Event& operator=(Event&& other) noexcept
    {
        m_payload = std::move(other.m_payload);
        return *this;
    }
};

#endif // _EVENT_H

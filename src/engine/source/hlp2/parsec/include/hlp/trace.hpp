#ifndef _HLP_TRACE_HPP
#define _HLP_TRACE_HPP

#include <algorithm>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <fmt/format.h>

namespace parsec
{
class Trace
{
public:
    using messageT = std::optional<std::string>;
    using traceContainerT = std::list<std::shared_ptr<Trace>>;
    using nestedTracesT = std::optional<traceContainerT>;

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
    // TODO: test if it is better to copy primitivies
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
    // TODO: test if it is better to copy primitivies
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
        // TODO: see if we can override the list comparison so we use the standard
        // comparison

        // Since we wrap Trace with a pointer we need to define custom coparison for inner
        // traces to compare the Trace if the pointers are not equal
        bool innerTracesEqual =
            // Optional comparison
            (m_innerTraces == other.m_innerTraces) ||
            // List comparison
            (m_innerTraces && other.m_innerTraces
             && std::equal(
                 m_innerTraces->cbegin(),
                 m_innerTraces->cend(),
                 other.m_innerTraces->cbegin(),
                 other.m_innerTraces->cend(),
                 [](const std::shared_ptr<Trace>& lhs, const std::shared_ptr<Trace>& rhs)
                 {
                     // Trace comparison
                     return (lhs == rhs) || (lhs && rhs && *lhs == *rhs);
                 }));
        return m_success == other.m_success && m_index == other.m_index
               && m_message == other.m_message && innerTracesEqual;
    }
    bool operator!=(const Trace& other) const { return !(*this == other); }

    bool success() const { return m_success; }
    size_t index() const { return m_index; }
    const messageT& message() const { return m_message; }
    messageT&& message() { return std::move(m_message); }
    const nestedTracesT& innerTraces() const { return m_innerTraces; }
    nestedTracesT&& innerTraces() { return std::move(m_innerTraces); }
};

inline const Trace& firstError(const Trace& trace)
{
    if (trace.innerTraces().has_value())
    {
        for (const auto& t : trace.innerTraces().value())
        {
            if (!t->success())
            {
                return firstError(*t);
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
            auto aux = getLeafErrors(*t);
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

    tr += trace.message().has_value()
              ? fmt::format("{} at {}\n", trace.message().value(), trace.index())
              : "succeeded \n";
    if (trace.innerTraces().has_value())
    {
        auto auxPrefix = prefix + (last ? "   " : "│  ");
        for (auto it = trace.innerTraces().value().begin();
             it != --trace.innerTraces().value().end();
             ++it)
        {
            tr += detailedTrace(**it, false, auxPrefix);
        }
        tr += detailedTrace(*trace.innerTraces().value().back(), true, auxPrefix);
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
            tr += fmt::format("{} at {}\n", e->message().value(), e->index());
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

} // namespace parsec

#endif // _HLP_TRACE_HPP

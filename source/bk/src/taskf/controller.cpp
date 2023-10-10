#include "controller.hpp"

#include "exprBuilder.hpp"
#include "tracer.hpp"
namespace bk::taskf
{

class Controller::TracerImpl final : public detail::Tracer
{
};

Controller::Controller(const FakePolicy& policy)
    : m_tf()
    , m_executor(1)
    , m_event()
    , m_traceables(policy.traceables())
    , m_expression(policy.expression())
{
    detail::ExprBuilder builder;
    std::unordered_map<std::string, std::shared_ptr<detail::Tracer>> traces;
    builder.build(m_expression, m_tf, &m_event, traces, m_traceables);
    for (auto& [name, trace] : traces)
    {
        m_traces.emplace(name, std::static_pointer_cast<TracerImpl>(trace));
    }
}

Controller::Controller(base::Expression expression, std::unordered_set<std::string> traceables)
    : m_tf()
    , m_executor(1)
    , m_event()
    , m_traceables(std::move(traceables))
    , m_expression(std::move(expression))
{
    detail::ExprBuilder builder;
    std::unordered_map<std::string, std::shared_ptr<detail::Tracer>> traces;
    builder.build(m_expression, m_tf, &m_event, traces, m_traceables);
    for (auto& [name, trace] : traces)
    {
        m_traces.emplace(name, std::static_pointer_cast<TracerImpl>(trace));
    }
}

base::RespOrError<Subscription> Controller::subscribe(const std::string& traceable, const Subscriber& subscriber)
{
    auto it = m_traces.find(traceable);
    if (it == m_traces.end())
    {
        return base::Error {"Traceable not found"};
    }

    return it->second->subscribe(subscriber);
}

void Controller::unsubscribe(const std::string& traceable, Subscription subscription)
{
    auto it = m_traces.find(traceable);
    if (it == m_traces.end())
    {
        return;
    }

    it->second->unsubscribe(subscription);
}
} // namespace bk::taskf

#include "controller.hpp"

#include "exprBuilder.hpp"
#include "tracer.hpp"
namespace bk::taskf
{

class Controller::TracerImpl final : public detail::Tracer
{
};

void Controller::build(base::Expression expression,
                       std::unordered_set<std::string> traceables,
                       std::function<void()> endCallback)
{
    if (m_isBuilt)
    {
        throw std::runtime_error {"The backend is already built"};
    }
    m_traceables = std::move(traceables);
    m_expression = std::move(expression);
    detail::ExprBuilder builder;
    std::unordered_map<std::string, std::shared_ptr<detail::Tracer>> traces;
    builder.build(m_expression, m_tf, &m_event, traces, m_traceables, endCallback);
    for (auto& [name, trace] : traces)
    {
        m_traces.emplace(name, std::static_pointer_cast<TracerImpl>(trace));
    }
    m_isBuilt = true;
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

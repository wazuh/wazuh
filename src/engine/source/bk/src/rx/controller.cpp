#include "controller.hpp"

#include "exprBuilder.hpp"
#include "tracer.hpp"

namespace bk::rx
{
class Controller::TracerImpl final : public detail::Tracer
{
};

Controller::Controller(const base::Expression& expression,
                       const std::unordered_set<std::string>& traceables,
                       const std::function<void()>& endCallback)
    : m_traceables {traceables}
    , m_expression {expression}
    , m_policyInput {m_policySubject.get_subscriber()}
{
    detail::ExprBuilder builder;
    std::unordered_map<std::string, std::shared_ptr<detail::Tracer>> traces;
    m_policyOutput = builder.build(expression, traces, m_traceables, m_policySubject.get_observable());
    for (auto& [name, trace] : traces)
    {
        m_traces.emplace(name, std::static_pointer_cast<TracerImpl>(trace));
    }
    if (endCallback != nullptr)
    {
        m_policyOutput.subscribe([endCallback](const RxEvent& event) { endCallback(); });
    }
    else
    {
        m_policyOutput.subscribe();
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

void Controller::unsubscribeAll()
{
    for (auto& [name, trace] : m_traces)
    {
        trace->unsubscribeAll();
    }
}

} // namespace bk::rx

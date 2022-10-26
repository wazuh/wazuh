#include "rxbk/rxFactory.hpp"

#include <stdexcept>

#include <fmt/format.h>

namespace rxbk
{

Tracer::Tracer()
    : m_output {m_subject.get_observable()}
    , m_subscriber {m_subject.get_subscriber()}
{
}

std::function<void(const std::string&)> Tracer::getTracerFn(std::string name) const
{
    return [=](const std::string& message)
    {
        if (m_subscriber.is_subscribed() && m_subject.has_observers())
        {
            m_subscriber.on_next(fmt::format("[{}] {}", name, message));
        }
    };
}

rx::composite_subscription Tracer::subscribe(rx::subscriber<std::string> s)
{
    return m_output.subscribe(s);
}

Controller::Controller()
    : m_envInput {m_envSubject.get_subscriber()}
{
}

void Controller::ingestEvent(RxEvent&& event)
{
    // TODO: handle errors notification/recovery
    if (m_envInput.is_subscribed())
    {
        m_envInput.on_next(std::move(event));
    }
}

void Controller::complete()
{
    if (m_envInput.is_subscribed())
    {
        m_envInput.on_completed();
    }
}

Observable Controller::getInternalInput() const
{
    return m_envSubject.get_observable();
}

Observable Controller::getOutput() const
{
    return m_envOutput;
}

void Controller::setOutput(Observable&& output)
{
    m_envOutput = std::move(output);
}

std::function<void(const std::string&)> Controller::addTracer(const std::string& name,
                                                              Tracer&& tracer)
{
    if (m_tracers.end() != m_tracers.find(name))
    {
        throw std::runtime_error(
            fmt::format("Engine rx factory: Tracer \"{}\" already exists.", name));
    }

    m_tracers[name] = std::move(tracer);
    return m_tracers[name].getTracerFn(name);
}

rx::composite_subscription Controller::listenOnTrace(const std::string& name,
                                                     rx::subscriber<std::string> s)
{
    if (m_tracers.end() == m_tracers.find(name))
    {
        throw std::runtime_error(
            fmt::format("Engine rx factory: Error, trying to listen on trace \"{}\", but "
                        "no trace with that name exists.",
                        name));
    }

    return m_tracers[name].subscribe(s);
}

rx::composite_subscription Controller::listenOnAllTrace(rx::subscriber<std::string> s)
{
    rx::composite_subscription cs;
    for (auto& [name, tracer] : m_tracers)
    {
        cs.add(tracer.subscribe(s));
    }

    return cs;
}

bool Controller::hasTracer(const std::string& name) const
{
    return m_tracers.end() != m_tracers.find(name);
}

const Tracer& Controller::getTracer(const std::string& name) const
{
    return m_tracers.at(name);
}

Observable rxFactory(const Observable& input,
                     const std::unordered_set<std::string>& assetNames,
                     base::Expression expression,
                     Controller& controller,
                     std::function<void(const std::string&)> tracerFn)
{
    if (assetNames.end() != assetNames.find(expression->getName()))
    {
        // If the expression has been visited before, there is no need to create the
        // tracer again, just retreive it
        if (controller.hasTracer(expression->getName()))
        {
            tracerFn = controller.getTracer(expression->getName())
                           .getTracerFn(expression->getName());
        }
        else
        {
            tracerFn = controller.addTracer(expression->getName(), Tracer {});
        }
    }

    // Handle pipelines
    if (expression->isOperation())
    {

        if (expression->isAnd())
        {
            Observable step1 = input.publish().ref_count();
            auto step2 = step1;
            auto op = expression->getPtr<base::And>();
            for (auto& operand : op->getOperands())
            {
                step2 = rxFactory(step2, assetNames, operand, controller, tracerFn)
                            .filter([](RxEvent result) { return result->success(); });
            }
            step2.subscribe();
            return step1;
        }
        else if (expression->isChain() || expression->isBroadcast())
        {
            // Input is passed to all conectables, and subscribed to output.
            // Regardless of result all conectables are going to operate.
            // Because the event is handled by a shared ptr the output is
            // simply the input.
            auto op = expression->getPtr<base::Operation>();
            Observable step1 = input.publish().ref_count();
            auto step2 = step1;
            for (auto& operand : op->getOperands())
            {
                step2 = rxFactory(step2, assetNames, operand, controller, tracerFn);
            }
            step2.subscribe();
            return step1.map(
                [](RxEvent result)
                {
                    result->setStatus(true);
                    return result;
                });
        }
        else if (expression->isOr())
        {
            auto op = expression->getPtr<base::Or>();
            Observable step1 = input.publish().ref_count();
            auto step2 = step1;
            for (auto& operand : op->getOperands())
            {
                step2 = rxFactory(step2, assetNames, operand, controller, tracerFn)
                            .filter([=](RxEvent result) { return result->failure(); });
            }
            step2.subscribe();
            return step1;
        }
        else if (expression->isImplication())
        {
            auto op = expression->getPtr<base::Implication>();
            Observable step = input.publish().ref_count();
            auto step1 = step;
            auto condition = std::make_shared<bool>(false);
            step1 =
                rxFactory(step1, assetNames, op->getOperands()[0], controller, tracerFn)
                    .filter(
                        [condition, tracer = tracerFn](RxEvent result)
                        {
                            *condition = result->success();
                            // TODO: temporal fix to display history of assets, we need to
                            // rethink tracers
                            tracer(std::string {fmt::format(
                                "[condition]:{}", *condition ? "success" : "failure")});
                            return result->success();
                        });
            rxFactory(step1, assetNames, op->getOperands()[1], controller, tracerFn)
                .subscribe();
            return step.map(
                [condition](RxEvent result)
                {
                    result->setStatus(*condition);
                    return result;
                });
        }
        else
        {
            throw std::runtime_error(
                fmt::format("Engine rx factory: Unsupported operation type."));
        }
    }
    else if (expression->isTerm())
    {
        auto term = expression->getPtr<base::Term<base::EngineOp>>();
        return input.map(
            [op = term->getFn(), tracer = tracerFn](RxEvent result)
            {
                *result = op(result->payload());
                // TODO: should we allow to not include tracer?
                tracer(std::string {result->trace()});
                return result;
            });
    }
    else
    {
        throw std::runtime_error("Engine rx factory: Unsupported connectable type.");
    }
}

Controller buildRxPipeline(const builder::Environment& environment)
{
    Controller controller;
    std::unordered_set<std::string> assetNames;
    std::transform(environment.assets().begin(),
                   environment.assets().end(),
                   std::inserter(assetNames, assetNames.begin()),
                   [](const auto& pair) { return pair.first; });
    auto output = rxFactory(controller.getInternalInput(),
                            assetNames,
                            environment.getExpression(),
                            controller);
    controller.setOutput(std::move(output));

    return controller;
}

} // namespace rxbk

#ifndef _RXCPP_FACTORY_H
#define _RXCPP_FACTORY_H

#include <rxcpp/rx.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include "_builder/environment.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"

namespace builder::internals::rxcppBackend
{

using RxcppEvent = std::shared_ptr<Result<Event>>;
using Observable = rxcpp::observable<RxcppEvent>;

class Tracer
{
private:
    rxcpp::subjects::subject<std::string> m_subject;
    rxcpp::observable<std::string> m_output;
    rxcpp::subscriber<std::string> m_subscriber;

public:
    Tracer()
        : m_output(m_subject.get_observable())
        , m_subscriber(m_subject.get_subscriber())
    {
    }

    auto getTracerFn(std::string name) -> std::function<void(const std::string&)>
    {
        return [=](const std::string& message)
        {
            if (m_subscriber.is_subscribed() && m_subject.has_observers())
            {
                m_subscriber.on_next(fmt::format("[{}] {}", name, message));
            }
        };
    }

    auto subscribe(rxcpp::subscriber<std::string>& s)
        -> decltype(m_output.subscribe(s))
    {
        return m_output.subscribe(s);
    }
};

class RxcppController
{
private:
    friend RxcppController buildRxcppPipeline(Environment definition);
    friend Observable
    rxcppFactory(const Observable& input,
                 Environment&,
                 Expression expression,
                 RxcppController& controller,
                 std::function<void(const std::string&)> tracerFn);

    rxcpp::subjects::subject<RxcppEvent> m_envSubject;
    rxcpp::subscriber<RxcppEvent> m_envInput;

    std::unordered_map<std::string, Tracer> m_tracers;

    RxcppController()
        : m_envInput(m_envSubject.get_subscriber())
    {
    }

public:
    rxcpp::observable<RxcppEvent> m_envOutput;
    void ingestEvent(RxcppEvent&& event)
    {
        if (m_envInput.is_subscribed())
        {
            m_envInput.on_next(std::move(event));
        }
        // TODO: notify environment is dead
    }

    // Returns subscription, in case you want to unsubscribe
    auto listenOnTrace(const std::string& name,
                       rxcpp::subscriber<std::string>& s)
        -> decltype(m_tracers[name].subscribe(s))
    {
        if (m_tracers.find(name) == m_tracers.end())
        {
            throw std::runtime_error(fmt::format(
                "Error, trying to listen on trace [{}], but no trace with that "
                "name exists",
                name));
        }
        return m_tracers[name].subscribe(s);
    }

    void listenOnAllTrace(rxcpp::subscriber<std::string> s)
    {
        for (auto& [name, tracer] : m_tracers)
        {
            tracer.subscribe(s);
        }
    }
};

Observable
rxcppFactory(const Observable& input,
             Environment& environment,
             Expression expression,
             RxcppController& controller,
             std::function<void(const std::string&)> tracerFn = nullptr)
{
    // Handle tracer things
    if (environment.assets().find(expression->getName()) !=
        environment.assets().end())
    {
        controller.m_tracers[expression->getName()] = Tracer {};

        tracerFn = controller.m_tracers[expression->getName()].getTracerFn(expression->getName());
    }

    // Handle pipelines
    std::cout << "rxcppFactory: " << expression->getName() << std::endl;
    if (expression->isOperation())
    {

        if (expression->isAnd())
        {
            Observable step = input;
            auto op = expression->getPtr<And>();
            for (auto& operand : op->getOperands())
            {
                step = rxcppFactory(
                           step, environment, operand, controller, tracerFn)
                           .filter([](RxcppEvent result)
                                   { return result->success(); });
            }
            return step;
        }
        else if (expression->isChain() || expression->isBroadcast())
        {
            // Input is passed to all conectables, and subscribed to output.
            // Regardless of result all conectables are going to operate.
            // Because the event is handled by a shared ptr the output is
            // simply the input.
            auto op = expression->getPtr<Operation>();
            Observable step1 = input.publish().ref_count();
            auto step2 = step1;
            for (auto& operand : op->getOperands())
            {
                rxcppFactory(step2, environment, operand, controller, tracerFn)
                    .subscribe();
            }
            return step1.map(
                [](RxcppEvent result)
                {
                    result->setStatus(true);
                    return result;
                });
        }
        else if (expression->isOr())
        {
            auto op = expression->getPtr<Or>();
            Observable step1 = input.publish().ref_count();
            auto step2 = step1;
            for (auto& operand : op->getOperands())
            {
                rxcppFactory(step2, environment, operand, controller, tracerFn)
                    .subscribe();
                step2 = step1.filter([=](RxcppEvent result)
                                     { return result->failure(); });
            }
            return step1.filter([=](RxcppEvent result)
                                { return result->success(); });
        }
        else if (expression->isImplication())
        {
            auto op = expression->getPtr<Implication>();
            Observable step = input.publish().ref_count();
            auto step1 = step;
            auto condition = std::make_shared<bool>(false);
            step1 =
                rxcppFactory(
                    step1, environment, op->getOperands()[0], controller, tracerFn)
                    .filter(
                        [condition](RxcppEvent result)
                        {
                            *condition = result->success();
                            return result->success();
                        });
            rxcppFactory(
                step1, environment, op->getOperands()[1], controller, tracerFn)
                .subscribe();
            return step.filter([condition](RxcppEvent result)
                               { return *condition; });
        }
        else
        {
            throw std::runtime_error(fmt::format("Unsupported operation type"));
        }
    }
    else if (expression->isTerm())
    {
        auto term = expression->getPtr<Term<EngineOp>>();
        return input.map(
            [op = term->getFn(), tracer = tracerFn](RxcppEvent result)
            {
                *result = op(result->popPayload());
                tracer(std::string{result->trace()});
                return result;
            });
    }
    else
    {
        throw std::runtime_error("Unsupported connectable type");
    }
}

RxcppController buildRxcppPipeline(Environment definition)
{
    RxcppController controller;
    auto input = controller.m_envSubject.get_observable();

    auto output =
        rxcppFactory(input, definition, definition.getExpression(), controller);
    controller.m_envOutput = output;

    return controller;
}

} // namespace builder::internals::rxcppBackend

#endif // _RXCPP_FACTORY_H

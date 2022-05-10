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

#include "_builder/connectable.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"
#include "_builder/operation.hpp"

namespace builder
{
namespace internals
{
namespace rxcppBackend
{

using RxcppEvent = std::shared_ptr<Result<Event<Json>>>;
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

    auto getTracerFn() -> std::function<void(std::string_view)>
    {
        return [=](std::string_view message)
        {
            if (m_subscriber.is_subscribed() && m_subject.has_observers())
            {
                m_subscriber.on_next(std::string {message});
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
    friend RxcppController
    buildRxcppPipeline(const std::shared_ptr<const Connectable>& definition);
    friend Observable
    rxcppFactory(const Observable& input,
                 const std::shared_ptr<const Connectable>& connectable,
                 RxcppController& controller,
                 std::function<void(std::string_view)> tracerFn,
                 std::shared_ptr<bool> localResult);

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
             const std::shared_ptr<const Connectable>& connectable,
             RxcppController& controller,
             std::function<void(std::string_view)> tracerFn = nullptr,
             std::shared_ptr<bool> localResult = nullptr)
{
    // Handle tracer things
    if (connectable->isAsset())
    {
        auto asAsset = connectable->getPtr<ConnectableAsset>();
        // TODO: Assets in differents subgrapsh may have the same name?
        controller.m_tracers[asAsset->m_name] = Tracer {};

        tracerFn = controller.m_tracers[asAsset->m_name].getTracerFn();
    }

    // Handle pipelines
    if (connectable->isGroup())
    {
        auto asGroup = connectable->getPtr<ConnectableGroup>();
        switch (asGroup->m_type)
        {
            case ConnectableGroup::CHAIN:
            {
                Observable step = input;
                int i = 0;
                if (localResult != nullptr)
                {
                    auto connectable = asGroup->m_connectables[i];
                    step = rxcppFactory(step, connectable, controller, tracerFn)
                               .filter(
                                   [=](RxcppEvent result)
                                   {
                                       *localResult = result->success();
                                       return *localResult;
                                   });
                    ++i;
                }
                for (i; i < asGroup->m_connectables.size(); i++)
                {
                    auto connectable = asGroup->m_connectables[i];
                    step = rxcppFactory(step, connectable, controller, tracerFn)
                               .filter([](RxcppEvent result)
                                       { return result->success(); });
                }
                return step;
            }
            case ConnectableGroup::FALLIBLE_CHAIN:
            {
                // Input is passed to all conectables, and subscribed to output.
                // Regardless of result all conectables are going to operate.
                // Because the event is handled by a shared ptr the output is
                // simply the input.
                Observable step1 = input.publish().ref_count();
                auto step2 = step1;
                for (auto& connectable : asGroup->m_connectables)
                {
                    rxcppFactory(step2, connectable, controller, tracerFn)
                        .subscribe();
                }
                return step1.tap(
                    [](RxcppEvent result) {
                        *result = makeSuccess(std::move(result->popEvent()),
                                              result->getTrace());
                    });
            }
            case ConnectableGroup::FIRST_SUCCESS:
            {
                Observable step1 = input.publish().ref_count();
                auto step2 = step1;
                std::shared_ptr<bool> localResult {new bool(false)};
                for (auto& connectable : asGroup->m_connectables)
                {
                    rxcppFactory(
                        step2, connectable, controller, tracerFn, localResult)
                        .subscribe();
                    step2 = step1.filter([=](RxcppEvent result)
                                         { return !*localResult; });
                }
                return step1.filter([=](RxcppEvent result)
                                    { return *localResult; });
            }
            case ConnectableGroup::FIRST_ERROR:
            {
                Observable step1 = input.publish().ref_count();
                auto step2 = step1;
                for (auto& connectable : asGroup->m_connectables)
                {
                    step2 =
                        rxcppFactory(step2, connectable, controller, tracerFn)
                            .filter([](RxcppEvent result)
                                    { return result->success(); });
                }
                step2.subscribe();
                return step1;
            }

            default:
                throw std::runtime_error(
                    fmt::format("Unsupported group type: {}", asGroup->m_type));
        }
    }
    else if (connectable->isOperation())
    {
        auto asOp = connectable->getPtr<ConnectableOperation<Operation>>();
        return input.tap(
            [op = asOp->getOperation(), tracerFn](RxcppEvent event)
            {
                *event = op(event->popEvent());
                tracerFn(event->getTrace());
            });
    }
    else
    {
        throw std::runtime_error("Unsupported connectable type");
    }
}

RxcppController
buildRxcppPipeline(const std::shared_ptr<const Connectable>& definition)
{
    RxcppController controller;
    auto input = controller.m_envSubject.get_observable();

    auto output = rxcppFactory(input, definition, controller);
    controller.m_envOutput = output;

    return controller;
}

} // namespace rxcppBackend
} // namespace internals
} // namespace builder

#endif // _RXCPP_FACTORY_H

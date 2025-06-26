#ifndef _BK_RX_EXPRBUILDER_HPP
#define _BK_RX_EXPRBUILDER_HPP

#include <functional>
#include <memory>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <base/logging.hpp>

#include "tracer.hpp"

namespace bk::rx::detail
{

class ExprBuilder
{
private:
    using RxEvent = std::shared_ptr<base::result::Result<base::Event>>;
    using Observable = rxcpp::observable<RxEvent>;

    struct BuildParams
    {
        Publisher publisher;
        std::unordered_map<std::string, std::shared_ptr<Tracer>>& traces;
        const std::unordered_set<std::string>& traceables;
    };

    Observable recBuild(const Observable& input, const base::Expression& expression, BuildParams& params)
    {
        // Error if empty expression
        if (expression == nullptr)
        {
            throw std::runtime_error {"Expression is null"};
        }

        // Create traceable if found and get the publisher function
        auto traceIt = params.traceables.find(expression->getName());
        if (traceIt != params.traceables.end())
        {
            if (params.traces.find(expression->getName()) == params.traces.end())
            {
                params.traces.emplace(expression->getName(), std::make_shared<Tracer>());
            }

            params.publisher = params.traces[expression->getName()]->publisher();
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
                    step2 = recBuild(step2, operand, params).filter([](RxEvent result) { return result->success(); });
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
                    step2 = recBuild(step2, operand, params);
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
                    step2 = recBuild(step2, operand, params).filter([=](RxEvent result) { return result->failure(); });
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
                step1 = recBuild(step1, op->getOperands()[0], params)
                            .filter(
                                [condition, tracer = params.publisher](RxEvent result)
                                {
                                    *condition = result->success();
                                    return result->success();
                                });
                recBuild(step1, op->getOperands()[1], params).subscribe();
                return step.map(
                    [condition](RxEvent result)
                    {
                        result->setStatus(*condition);
                        return result;
                    });
            }
            else
            {
                throw std::runtime_error("Unsupported operation type");
            }
        }
        else if (expression->isTerm())
        {
            auto term = expression->getPtr<base::Term<base::EngineOp>>();
            return input.map(
                [op = term->getFn(), tracer = params.publisher, name = expression->getName()](RxEvent result)
                {
                    try
                    {
                        *result = op(result->payload());
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR("Unexpected error processing term: {} in '{}' with {}.",
                                  e.what(),
                                  name,
                                  result->payload()->str());
                        const std::string errorMsg =
                            fmt::format(R"([{}] -> Failure: operation throw exception.)", name);
                        *result = base::result::makeFailure(result->payload(), errorMsg);
                    }

                    // TODO: should we allow to not include tracer?
                    if (tracer != nullptr)
                    {
                        tracer(std::string {result->trace()}, result->success());
                    }
                    return result;
                });
        }
        else
        {
            throw std::runtime_error("Unsupported expression type");
        }
    }

public:
    virtual ~ExprBuilder() = default;
    ExprBuilder() = default;

    Observable build(const base::Expression& expression,
                     std::unordered_map<std::string, std::shared_ptr<Tracer>>& traces,
                     const std::unordered_set<std::string>& traceables,
                     const Observable& input)
    {
        BuildParams params {.publisher = nullptr, .traces = traces, .traceables = traceables};
        auto output = recBuild(input, expression, params);

        return output;
    }
};

} // namespace bk::rx::detail

#endif // _BK_RX_EXPRBUILDER_HPP

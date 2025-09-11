#ifndef _BK_TASKF_EXPRBUILDER_HPP
#define _BK_TASKF_EXPRBUILDER_HPP

#include <functional>
#include <memory>

#include <taskflow/taskflow.hpp>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>

#include "tracer.hpp"

namespace bk::taskf::detail
{

class ITask
{
protected:
    bool m_connected;

    void assertConnect()
    {
        if (m_connected)
        {
            throw std::runtime_error {"Task already connected"};
        }

        m_connected = true;
    }

public:
    virtual ~ITask() = default;

    ITask()
        : m_connected(false)
    {
    }

    virtual tf::Task& input() = 0;

    virtual void on(tf::Task& success, tf::Task& failure) = 0;
};

using ComplexTask = std::shared_ptr<ITask>;

class TaskTerm : public ITask
{
private:
    tf::Task m_task;
    base::EngineOp m_op;
    Publisher m_publisher;
    void* m_data;
    tf::Taskflow& m_tf;

public:
    TaskTerm(base::EngineOp op, const std::string& name, Publisher publisher, void* data, tf::Taskflow& tf)
        : ITask()
        , m_op(op)
        , m_publisher(publisher)
        , m_data(data)
        , m_tf(tf)
        , m_task(tf.placeholder().name(name))
    {
    }

    tf::Task& input() override { return m_task; }

    void on(tf::Task& success, tf::Task& failure) override
    {
        assertConnect();
        m_task.work(
            [fn = m_op, publisher = m_publisher, data = m_data]()
            {
                auto& event = *static_cast<base::Event*>(data);
                auto res = fn(event);
                if (publisher)
                {
                    publisher(res.trace(), res.success());
                }

                return res.success() ? 0 : 1;
            });

        m_task.precede(success, failure);
    }
};

class TaskBroadcast : public ITask
{
private:
    tf::Task m_input;
    tf::Task m_output;

public:
    TaskBroadcast(tf::Taskflow& tf)
        : ITask()
        , m_input(tf.placeholder().name("broadcast_in"))
        , m_output(tf.emplace([]() { return 0; }).name("broadcast_out"))
    {
    }

    tf::Task& input() override { return m_input; }

    void addStep(ComplexTask step, tf::Taskflow& tf)
    {
        m_input.precede(step->input());
        auto broadcastStep = tf.placeholder().name("broadcast_step").precede(m_output);
        step->on(broadcastStep, broadcastStep);
    }

    void on(tf::Task& success, tf::Task& failure) override
    {
        assertConnect();
        m_output.precede(success, failure);
    }
};

class TaskChain : public ITask
{
private:
    std::vector<ComplexTask> m_steps;
    tf::Task m_output;

public:
    TaskChain(tf::Taskflow& tf)
        : ITask()
        , m_output(tf.emplace([]() { return 0; }).name("chain_out"))
    {
    }

    tf::Task& input() override { return m_steps.front()->input(); }

    void addStep(ComplexTask step)
    {
        if (!m_steps.empty())
        {
            m_steps.back()->on(step->input(), step->input());
        }

        m_steps.emplace_back(step);
    }

    void on(tf::Task& success, tf::Task& failure) override
    {
        assertConnect();
        m_steps.back()->on(m_output, m_output);
        m_output.precede(success, failure);
    }
};

class TaskImplication : public ITask
{
private:
    tf::Task m_input;
    tf::Task m_outputSuccess;
    tf::Task m_outputFailure;

public:
    TaskImplication(tf::Taskflow& tf)
        : ITask()
        , m_input(tf.placeholder().name("implication_in"))
        , m_outputSuccess(tf.emplace([]() { return 0; }).name("implication_out_success"))
        , m_outputFailure(tf.emplace([]() { return 0; }).name("implication_out_failure"))
    {
    }

    tf::Task& input() override { return m_input; }

    void set(ComplexTask condition, ComplexTask then)
    {
        m_input.precede(condition->input());
        condition->on(then->input(), m_outputFailure);
        then->on(m_outputSuccess, m_outputSuccess);
    }

    void on(tf::Task& success, tf::Task& failure) override
    {
        assertConnect();
        m_outputSuccess.precede(success);
        m_outputFailure.precede(failure);
    }
};

class TaskAnd : public ITask
{
private:
    tf::Task m_input;
    std::vector<ComplexTask> m_steps;
    tf::Task m_outputFailure;
    tf::Task m_outputSuccess;

public:
    TaskAnd(tf::Taskflow& tf)
        : ITask()
        , m_input(tf.placeholder().name("and_in"))
        , m_outputSuccess(tf.emplace([]() { return 0; }).name("and_out_success"))
        , m_outputFailure(tf.emplace([]() { return 0; }).name("and_out_failure"))
    {
    }

    tf::Task& input() override { return m_input; }

    void addStep(ComplexTask step)
    {
        if (m_steps.empty())
        {
            m_input.precede(step->input());
        }
        else
        {
            m_steps.back()->on(step->input(), m_outputFailure);
        }

        m_steps.emplace_back(step);
    }

    void on(tf::Task& success, tf::Task& failure) override
    {
        assertConnect();
        m_steps.back()->on(m_outputSuccess, m_outputFailure);
        m_outputSuccess.precede(success);
        m_outputFailure.precede(failure);
    }
};

class TaskOr : public ITask
{
private:
    tf::Task m_input;
    std::vector<ComplexTask> m_steps;
    tf::Task m_outputSuccess;
    tf::Task m_outputFailure;

public:
    TaskOr(tf::Taskflow& tf)
        : ITask()
        , m_input(tf.placeholder().name("or_in"))
        , m_outputSuccess(tf.emplace([]() { return 0; }).name("or_out_success"))
        , m_outputFailure(tf.emplace([]() { return 0; }).name("or_out_failure"))
    {
    }

    tf::Task& input() override { return m_input; }

    void addStep(ComplexTask step)
    {
        if (m_steps.empty())
        {
            m_input.precede(step->input());
        }
        else
        {
            m_steps.back()->on(m_outputSuccess, step->input());
        }

        m_steps.emplace_back(step);
    }

    void on(tf::Task& success, tf::Task& failure) override
    {
        assertConnect();
        m_steps.back()->on(m_outputSuccess, m_outputFailure);
        m_outputSuccess.precede(success);
        m_outputFailure.precede(failure);
    }
};

class ExprBuilder
{
private:
    struct BuildParams
    {
        tf::Taskflow& tf;
        Publisher publisher;
        void* data;
        std::unordered_map<std::string, std::shared_ptr<Tracer>>& traces;
        const std::unordered_set<std::string>& traceables;
    };

    ComplexTask buildTerm(const base::Term<base::EngineOp>& term, BuildParams& params)
    {
        auto taskTerm =
            std::make_shared<TaskTerm>(term.getFn(), term.getName(), params.publisher, params.data, params.tf);
        return taskTerm;
    }

    ComplexTask buildBroadcast(const base::Broadcast& broadcast, BuildParams& params)
    {
        auto broadcastTask = std::make_shared<TaskBroadcast>(params.tf);

        // Build each operand
        for (auto& exprOperand : broadcast.getOperands())
        {
            broadcastTask->addStep(recBuild(exprOperand, params), params.tf);
        }

        return broadcastTask;
    }

    ComplexTask buildChain(const base::Chain& chain, BuildParams& params)
    {
        auto chainTask = std::make_shared<TaskChain>(params.tf);

        // Build each operand
        for (auto& exprOperand : chain.getOperands())
        {
            chainTask->addStep(recBuild(exprOperand, params));
        }

        return chainTask;
    }

    ComplexTask buildImplication(const base::Implication& implication, BuildParams& params)
    {
        auto implicationTask = std::make_shared<TaskImplication>(params.tf);

        // Build each operand
        auto conditionTask = recBuild(implication.getOperands()[0], params);
        auto thenTask = recBuild(implication.getOperands()[1], params);

        implicationTask->set(conditionTask, thenTask);

        return implicationTask;
    }

    ComplexTask buildAnd(const base::And& andExpr, BuildParams& params)
    {
        auto andTask = std::make_shared<TaskAnd>(params.tf);

        // Build each operand
        for (auto& exprOperand : andExpr.getOperands())
        {
            andTask->addStep(recBuild(exprOperand, params));
        }

        return andTask;
    }

    ComplexTask buildOr(const base::Or& orExpr, BuildParams& params)
    {
        auto orTask = std::make_shared<TaskOr>(params.tf);

        // Build each operand
        for (auto& exprOperand : orExpr.getOperands())
        {
            orTask->addStep(recBuild(exprOperand, params));
        }

        return orTask;
    }

    ComplexTask recBuild(const base::Expression& expression, BuildParams& params)
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
                params.traces.emplace(expression->getName(), std::make_unique<Tracer>());
            }

            params.publisher = params.traces[expression->getName()]->publisher();
        }

        if (expression->isTerm())
        {
            return buildTerm(*expression->getPtr<base::Term<base::EngineOp>>(), params);
        }
        else if (expression->isOperation())
        {
            if (expression->isBroadcast())
            {
                return buildBroadcast(*expression->getPtr<base::Broadcast>(), params);
            }
            else if (expression->isChain())
            {
                return buildChain(*expression->getPtr<base::Chain>(), params);
            }
            else if (expression->isImplication())
            {
                return buildImplication(*expression->getPtr<base::Implication>(), params);
            }
            else if (expression->isAnd())
            {
                return buildAnd(*expression->getPtr<base::And>(), params);
            }
            else if (expression->isOr())
            {
                return buildOr(*expression->getPtr<base::Or>(), params);
            }
            else
            {
                throw std::runtime_error("Unsupported operation type");
            }
        }
        else
        {
            throw std::runtime_error("Unsupported expression type");
        }
    }

public:
    virtual ~ExprBuilder() = default;
    ExprBuilder() = default;

    void build(const base::Expression& expression,
               tf::Taskflow& tf,
               void* data,
               std::unordered_map<std::string, std::shared_ptr<Tracer>>& traces,
               const std::unordered_set<std::string>& traceables,
               std::function<void()> endCallback = nullptr)
    {
        BuildParams params {.tf = tf, .publisher = nullptr, .data = data, .traces = traces, .traceables = traceables};
        // As complex task are not finished until output is connected we need to force the connection
        auto finalTask = recBuild(expression, params);
        auto output = tf.placeholder().name("output");
        if (endCallback)
        {
            output.work(endCallback);
        }
        finalTask->on(output, output);
    }
};

} // namespace bk::taskf::detail

#endif // _BK_TASKF_EXPRBUILDER_HPP

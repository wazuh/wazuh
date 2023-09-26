#ifndef BK_TFBK_HPP
#define BK_TFBK_HPP

#include <memory>
#include <string>

#include <taskflow/taskflow.hpp>

#include <bk/iBk.hpp>

#include <baseTypes.hpp>
#include <expression.hpp>

namespace tfbk
{

namespace
{
constexpr int SUCCESS = 0;
constexpr int FAILURE = 1;

void setTaskSuccess(tf::Task& task, const std::string& name)
{
    task.name(name).work(
        [name]()
        {
            std::cout << "Task " << name << " success" << std::endl;
            return SUCCESS;
        });
}

void setTaskFailure(tf::Task& task, const std::string& name)
{
    task.name(name).work(
        [name]()
        {
            std::cout << "Task " << name << " failure" << std::endl;
            return FAILURE;
        });
}

} // namespace

template<typename T = std::string>
class Event : public bk::IEvent<T>
{
protected:
    T m_data;
    std::list<std::string> m_traces;

public:
    Event& setData(T&& data) override
    {
        m_data = std::move(data);
        return *this;
    }

    const T& getData() const override { return m_data; }

    Event& addTrace(std::string&& trace) override
    {
        m_traces.push_back(std::move(trace));
        return *this;
    }

    const std::list<std::string>& getTraces() const override { return m_traces; }

    void clearTraces() override { m_traces.clear(); }
};

template<typename T = std::string>
class TfBk : public bk::IBk<T>
{

protected:
    tf::Taskflow m_tf;
    tf::Executor m_executor;
    Event<T> m_event; // Never replce this attribute after build is called (it is used as a store result)
    bool m_builded; // TODO Bad way, change this

    tf::Task build(const base::Expression& expression, tf::Task& parent, bool ignoreResult = false)
    {
        if (expression == nullptr)
        {
            // Whens a filter is empty, it is considered as a success ? (TODO: check this)
            throw std::runtime_error("Expression is null");
        }

        auto task = m_tf.placeholder(); // Add output task to taskflow graph
        bool hasParent = !parent.empty();

        if (expression->isTerm())
        {
            auto term = expression->getPtr<base::Term<base::EngineOp>>();

            task.name("term").data(&m_event);
            if (ignoreResult)
                task.work(
                    [operation = term->getFn(), task]()
                    {
                        auto& event = *static_cast<Event<T>*>(task.data());
                        auto result = operation(event.getData());
                        event.addTrace(result.popTrace());
                    });
            else
            {
                task.work(
                    [operation = term->getFn(), task]()
                    {
                        auto& event = *static_cast<Event<T>*>(task.data());
                        auto result = operation(event.getData());
                        event.addTrace(result.popTrace());
                        return result.success() ? SUCCESS : FAILURE;
                    });
            }
            // If not root, add dependency
            if (hasParent)
            {
                task.succeed(parent);
            }
        }
        else if (expression->isOperation())
        {
            if (expression->isBroadcast())
            {
                setTaskSuccess(task, "broadcast");

                auto operands = expression->getPtr<base::Broadcast>()->getOperands();
                if (operands.size() == 0)
                {
                    throw std::runtime_error("Broadcast has no operands");
                }
                for (auto& operand : operands)
                {
                    auto subTask = build(operand, parent, true);
                    task.succeed(subTask);
                }
            }
            else if (expression->isChain())
            {
                auto operands = expression->getPtr<base::Chain>()->getOperands();
                if (operands.size() == 0)
                {
                    throw std::runtime_error("Chain has no operands");
                }

                auto prevTask = parent;
                for (auto& operand : operands)
                {
                    prevTask = build(operand, prevTask, true);
                }
                // Set result of chain as result of last task
                // m_tf.erase(task);
                // task = prevTask;

                // Set result of chain of true
                setTaskSuccess(task, "chain");
                task.succeed(prevTask);
            }
            else if (expression->isImplication())
            {
                auto operands = expression->getPtr<base::Implication>()->getOperands();
                if (operands.size() != 2)
                {
                    throw std::runtime_error("Implication has not 2 operands");
                }

                if (!hasParent)
                {
                    // The parent is needed for TF to work properly at this point
                    parent =
                        m_tf.emplace([]() { std::cout << "Root implication" << std::endl; }).name("root implication");
                }

                std::shared_ptr<std::atomic<int>> result = std::make_shared<std::atomic<int>>(SUCCESS);

                auto condTask = build(operands[0], parent).name("cond implication");
                auto eTask = tf::Task();
                auto successTask = build(operands[1], eTask).name("success implication");
                auto failTask = m_tf.emplace(
                                        [result]()
                                        {
                                            result->store(FAILURE);
                                            return SUCCESS;
                                        })
                                    .name("fail implication");

                condTask.precede(successTask, failTask);

                task.name("implication output");
                task.succeed(failTask);
                task.succeed(successTask, successTask);
                task.work([result]() { return result->load(); });
            }
            else if (expression->isOr())
            {
                auto operands = expression->getPtr<base::Or>()->getOperands();
                if (operands.empty())
                {
                    throw std::runtime_error("Or has no operands");
                }

                if (!hasParent)
                {
                    // The parent is needed for TF to work properly at this point
                    parent = m_tf.emplace(
                                     []()
                                     {
                                         std::cout << "Root or" << std::endl;
                                         return FAILURE;
                                     })
                                 .name("root or");
                }

                std::shared_ptr<std::atomic<int>> result = std::make_shared<std::atomic<int>>(FAILURE);
                auto successTask = m_tf.emplace(
                                           [result]()
                                           {
                                               result->store(SUCCESS);
                                               return SUCCESS;
                                           })
                                       .name("success or")
                                       .precede(task);

                auto lastTask = parent;
                auto eTask = tf::Task();
                for (auto& operand : operands)
                {
                    auto subTask = build(operand, eTask);
                    lastTask.precede(successTask, subTask);
                    lastTask = subTask;
                }
                lastTask.precede(successTask, task);

                task.name("or output");
                task.work([result]() { return result->load(); });
            }
            else if (expression->isAnd())
            {
                auto operands = expression->getPtr<base::And>()->getOperands();
                if (operands.empty())
                {
                    throw std::runtime_error("And has no operands");
                }

                if (!hasParent)
                {
                    // The parent is needed for TF to work properly at this point
                    parent = m_tf.emplace(
                                     []()
                                     {
                                         std::cout << "Root and" << std::endl;
                                         return SUCCESS;
                                     })
                                 .name("root and");
                }

                std::shared_ptr<std::atomic<int>> result = std::make_shared<std::atomic<int>>(SUCCESS);
                auto failTask = m_tf.emplace(
                                        [result]()
                                        {
                                            result->store(FAILURE);
                                            return FAILURE;
                                        })
                                    .name("fail and")
                                    .precede(task);

                auto lastTask = parent;
                auto eTask = tf::Task();
                for (auto& operand : operands)
                {
                    auto subTask = build(operand, eTask);
                    lastTask.precede(subTask, failTask);
                    lastTask = subTask;
                }
                lastTask.precede(task, failTask);

                task.name("and output");
                task.work([result]() { return result->load(); });
            }
            else
            {
                throw std::runtime_error("Unsupported operation");
            }
        }

        else
        {
            throw std::runtime_error("Unsupported expression type");
        }

        if (!task.has_work())
        {
            throw std::runtime_error("Task has no work");
        }

        if (!hasParent)
        {
            std::cout << "Root task" << std::endl;
        }

        return task;
    }

public:
    TfBk()
        : m_tf()
        , m_executor(1)
        , m_event()
        , m_builded (false) {};
    ~TfBk() = default;

    void build(const base::Expression& expression) override
    {
        m_builded = true;
        auto eTask = tf::Task();
        build(expression, eTask);
    }

    void ingest(T&& event) override
    {
        m_event.setData(std::move(event));
        m_executor.run(m_tf).wait();
    }

    const bk::IEvent<T>& getEvent() const override { return m_event; }
    bk::IEvent<T>& getEvent() override { return m_event; }

    std::string print() const override
    {
        // std::cout << "-------------------" << '\n';
        // m_tf.for_each_task([](tf::Task task) { std::cout << task.name() << '\n'; });
        // std::cout << "-------------------" << '\n';

        return m_tf.dump();
    }

    // Complete the taskflow and clear the event,
    void close() override
    {
        m_event = Event<T>();
        m_tf.clear();
    }

    bool isBuilded() const override { return m_builded; }
};

} // end of namespace tfbk

#endif
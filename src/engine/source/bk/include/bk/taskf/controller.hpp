#ifndef BK_TASKF_CONTROLLER_HPP
#define BK_TASKF_CONTROLLER_HPP

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

#include <taskflow/taskflow.hpp>

#include <bk/icontroller.hpp>
#include <expression.hpp>

namespace bk::taskf
{

class Trace final
    : public ITrace
    , public std::enable_shared_from_this<Trace>
{
private:
    std::string m_name;
    std::unordered_map<Subscription, Subscriber> m_subscribers;

    Subscription m_nextSubId {0};
    Subscription nextSubId() { return m_nextSubId++; }

    std::shared_mutex m_subscribersMutex;

public:
    ~Trace() = default;

    inline const std::string& name() const override { return m_name; }

    inline base::RespOrError<Subscription> subscribe(const Subscriber& subscriber) override
    {
        std::unique_lock lock {m_subscribersMutex};
        auto id = nextSubId();
        if (m_subscribers.find(id) != m_subscribers.end())
        {
            return base::Error {"Subscription already exists"};
        }

        m_subscribers.emplace(id, subscriber);
        return id;
    }

    inline void unsubscribe(Subscription subscription) override
    {
        std::unique_lock lock {m_subscribersMutex};
        m_subscribers.erase(subscription);
    }

    Publisher publisher() override
    {
        return [thisPtr = this->weak_from_this()](std::string_view message)
        {
            auto thisShared = thisPtr.lock();
            std::shared_lock lock {thisShared->m_subscribersMutex};
            for (const auto& [_, subscriber] : thisShared->m_subscribers)
            {
                subscriber(message);
            }
        };
    }
};

class Controller final : public IController
{
private:
    std::unordered_map<std::string, std::shared_ptr<Trace>> m_traces; ///< Traces
    std::unordered_set<std::string> m_traceables;                     ///< Traceables

    tf::Taskflow m_tf;       ///< Taskflow
    tf::Executor m_executor; ///< Executor

    base::Event m_event; ///< Shared event between the tasks

    static constexpr size_t SUCCESS = 0;
    static constexpr size_t FAILURE = 1;

    static inline size_t toTfRes(const base::result::Result<base::Event>& result)
    {
        return result.success() ? SUCCESS : FAILURE;
    }

    static void setWorkSuccess(tf::Task& task, const std::string& name)
    {
        task.name(name).work([name]() { return SUCCESS; });
    }

    static void setWorkFailure(tf::Task& task, const std::string& name)
    {
        task.name(name).work([name]() { return FAILURE; });
    }

    using RetWork = std::function<size_t()>;
    using Work = std::function<void()>;

    Work getWork(base::EngineOp&& job, void* eventPtr, Trace::Publisher publisher)
    {
        return [job = std::move(job), eventPtr, publisher]()
        {
            auto& event = *static_cast<base::Event*>(eventPtr);
            auto res = job(event);
            if (publisher != nullptr)
            {
                publisher(res.trace());
            }
        };
    }

    RetWork getRetWork(base::EngineOp&& job, void* eventPtr, Trace::Publisher publisher)
    {
        return [job = std::move(job), eventPtr, publisher]() -> size_t
        {
            auto& event = *static_cast<base::Event*>(eventPtr);
            auto res = job(event);
            if (publisher != nullptr)
            {
                publisher(res.trace());
            }
            return toTfRes(res);
        };
    }

    tf::Task build(const base::Expression& expression,
                   tf::Task& parent,
                   bool needResult = false,
                   Trace::Publisher publisher = nullptr)
    {
        // Error if empty expression
        if (expression == nullptr)
        {
            throw std::runtime_error {"Expression is null"};
        }

        // Create traceable if found and get the publisher function
        auto traceIt = m_traceables.find(expression->getName());
        if (traceIt != m_traceables.end())
        {
            // TODO The name of expression can be repeated in the chain
            if (m_traces.find(expression->getName()) != m_traces.end())
            {
                throw std::runtime_error {"Trace already exists"};
            }
            m_traces.emplace(expression->getName(), std::make_unique<Trace>());
            // TODO publisher of the parameter is always replaced by the trace publisher?
            publisher = m_traces[expression->getName()]->publisher();
        }

        auto task = m_tf.placeholder();
        bool hasParent = !parent.empty();

        // Term
        if (expression->isTerm())
        {
            auto term = expression->getPtr<base::Term<base::EngineOp>>();

            // Create task
            task.name(term->getName());
            if (needResult)
            {
                task.work(getRetWork(term->getFn(), &m_event, publisher));
            }
            else
            {
                task.work(getWork(term->getFn(), &m_event, publisher));
            }

            // If not root, add dependency
            if (hasParent)
            {
                task.succeed(parent);
            }
        }
        // Operation
        else if (expression->isOperation())
        {
            auto checkOpSize =
                [](const auto& op, const std::string& name, const size_t size = 1, bool isMinSize = true) -> void
            {
                if (isMinSize && op.size() < size)
                {
                    throw std::runtime_error(fmt::format("Operation '{}' must have at least {} operands", name, size));
                }
                else if (!isMinSize && op.size() != size)
                {
                    throw std::runtime_error(fmt::format("Operation '{}' must have {} operands", name, size));
                }
            };
            // Broadcast
            if (expression->isBroadcast())
            {
                setWorkSuccess(task, "Broadcast");

                auto operands = expression->getPtr<base::Broadcast>()->getOperands();
                checkOpSize(operands, "Broadcast");

                for (auto& operand : operands)
                {
                    auto subTask = build(operand, parent, true, publisher);
                    task.succeed(subTask);
                }
            }
            // Chain
            else if (expression->isChain())
            {
                setWorkSuccess(task, "chain");

                auto operands = expression->getPtr<base::Chain>()->getOperands();
                checkOpSize(operands, "Chain");

                auto prevTask = parent;
                for (auto& operand : operands)
                {
                    prevTask = build(operand, prevTask, true, publisher);
                }
                task.succeed(prevTask);
            }
            // Implication
            else if (expression->isImplication())
            {
                auto operands = expression->getPtr<base::Implication>()->getOperands();
                checkOpSize(operands, "Implication", 2);

                if (!hasParent)
                {
                    parent = m_tf.emplace([]() {}).name("root implication");
                }

                std::shared_ptr<std::atomic<int>> result = std::make_shared<std::atomic<int>>(SUCCESS);

                auto condTask = build(operands[0], parent, false, publisher).name("cond implication");
                auto eTask = tf::Task();
                auto successTask = build(operands[1], eTask, false, publisher).name("success implication");
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
                checkOpSize(operands, "Or");

                if (!hasParent)
                {
                    parent = m_tf.emplace([]() { return FAILURE; }).name("root or");
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
                    auto subTask = build(operand, eTask, false, publisher);
                    lastTask.precede(successTask, subTask);
                    lastTask = subTask;
                }
                lastTask.precede(successTask, task);

                task.name("or output");
                task.work([result]() { return result->load(); });
            }
            // And
            else if (expression->isAnd())
            {
                auto operands = expression->getPtr<base::And>()->getOperands();
                checkOpSize(operands, "And");

                if (!hasParent)
                {
                    parent = m_tf.emplace([]() { return SUCCESS; }).name("root and");
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
                    auto subTask = build(operand, eTask, false, publisher);
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

        return task;
    }

public:
    Controller() = delete;
    Controller(const Controller&) = delete;

    ~Controller() = default;

    // TODO: Use builder interface, define it, don't use the actual builder interface
    // We need the traceables to be defined before the expression is built
    Controller(const base::Expression& expression)
        : m_tf()
        , m_executor(1)
        , m_event()
    {
        auto eTask = tf::Task();
        build(expression, eTask);
    }

    void ingest(base::Event&& event) override {
        m_event = std::move(event);
        m_executor.run(m_tf).wait();
    }
    
    base::Event ingestGet(base::Event&& event) override {
        ingest(std::move(event));
        return std::move(m_event);
    };

    void start() override {};
    void stop() override {};

    const std::unordered_set<std::string>& getTraceables() const override { return m_traceables; }

    base::RespOrError<ITrace::Subscription> subscribe(const std::string& traceable,
                                                      const ITrace::Subscriber& subscriber) override
    {
        auto it = m_traces.find(traceable);
        if (it == m_traces.end())
        {
            return base::Error {"Traceable not found"};
        }

        return it->second->subscribe(subscriber);
    }

    void unsubscribe(const std::string& traceable, ITrace::Subscription subscription) override
    {
        auto it = m_traces.find(traceable);
        if (it == m_traces.end())
        {
            return;
        }

        it->second->unsubscribe(subscription);
    }

    std::string dump() const { return m_tf.dump(); }
};

} // namespace bk::taskf

#endif // BK_TASKF_CONTROLLER_HPP

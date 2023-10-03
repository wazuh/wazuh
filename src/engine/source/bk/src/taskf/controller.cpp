#include "controller.hpp"

namespace
{
constexpr int SUCCESS = 0; ///< Success return value (First index in task result)
constexpr int FAILURE = 1; ///< Failure return value (Second index in task result)

using RetWork = std::function<int()>; ///< Definition of a taskflow work that is a conditional task (weak dependency)
using Work = std::function<void()>;   ///< Definition of a taskflow work that is a task (String dependency)

/**
 * @brief Convert a base::result::Result to a taskflow result
 *
 */
inline int toTfRes(const base::result::Result<base::Event>& result)
{
    return result.success() ? SUCCESS : FAILURE;
}

/**
 * @brief Set the work of a task to a success
 *
 * @param task Task to set the work
 * @param name Name of the task
 */
void setWorkSuccess(tf::Task& task, const std::string& name)
{
    task.name(name).work([name]() { return SUCCESS; });
}

/**
 * @brief Set the work of a task to a failure
 *
 * @param task Task to set the work
 * @param name Name of the task
 */
void setWorkFailure(tf::Task& task, const std::string& name)
{
    task.name(name).work([name]() { return FAILURE; });
}

void setWork(tf::Task& task, const std::string& name)
{
    task.name(name).work([]() {});
}

/**
 * @brief Create a contional work of a task from a base::EngineOp to a apply it to a base::Event
 *
 * @param job the base::EngineOp to apply to the base::Event
 * @param eventPtr Pointer to the base::Event
 * @param publisher Publisher function to publish the trace
 * @return Work The work of the task
 */
Work getWork(base::EngineOp&& job, void* eventPtr, bk::taskf::Controller::Publisher publisher)
{
    return [job = std::move(job), eventPtr, publisher = std::move(publisher)]()
    {
        auto& event = *static_cast<base::Event*>(eventPtr);
        auto res = job(event);
        if (publisher != nullptr)
        {
            publisher(res.trace());
        }
    };
}

/**
 * @brief Create a non-conditional work of a task from a base::EngineOp to a apply it to a base::Event
 *
 * @param job the base::EngineOp to apply to the base::Event
 * @param eventPtr Pointer to the base::Event
 * @param publisher Publisher function to publish the trace
 * @return Work The work of the task
 */
RetWork getRetWork(base::EngineOp&& job, void* eventPtr, bk::taskf::Controller::Publisher publisher)
{
    return [job = std::move(job), eventPtr, publisher = std::move(publisher)]() -> size_t
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
} // namespace

namespace bk::taskf
{

/**
 * @brief Interface for the trace
 *
 * The trace is the way to get the data from each traceable expression when it is evaluated in the backend.
 */
class Controller::TraceImpl final : public std::enable_shared_from_this<TraceImpl>
{
private:
    std::string m_name;                                         ///< Name of the trace
    std::unordered_map<Subscription, Subscriber> m_subscribers; ///< subscription id -> subscriber map

    Subscription m_nextSubId {0};                      ///< Next subscription id
    Subscription nextSubId() { return m_nextSubId++; } ///< Get the next subscription id

    std::shared_mutex m_subscribersMutex; ///< Mutex for the subscribers

public:
    ~TraceImpl() = default;

    /**
     * @brief Get the name of the trace.
     *
     * @return const std::string& The name of the trace.
     */
    inline const std::string& name() const { return m_name; }

    /**
     * @brief Subscribe `subscriber` to the trace.
     *
     * @param subscriber The subscriber to subscribe.
     * @return base::RespOrError<Subscription> The subscription identifier or error if the subscription failed.
     */
    inline base::RespOrError<Subscription> subscribe(const Subscriber& subscriber)
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

    /**
     * @brief Unsubscribe a subscriber from the trace.
     *
     * @param subscription The subscription identifier to unsubscribe.
     */
    inline void unsubscribe(Subscription subscription)
    {
        std::unique_lock lock {m_subscribersMutex};
        m_subscribers.erase(subscription);
    }

    /**
     * @copydoc bk::ITrace::publisher
     */
    Publisher publisher()
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

tf::Task Controller::build(const base::Expression& expression, tf::Task& parent, bool needResult, Publisher publisher)
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
        if (m_traces.find(expression->getName()) != m_traces.end())
        {
            throw std::runtime_error {"TraceImpl already exists"};
        }
        m_traces.emplace(expression->getName(), std::make_unique<TraceImpl>());
        publisher = m_traces[expression->getName()]->publisher();
    }

    auto task = m_tf.placeholder(); // Change name output task
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
            auto operands = expression->getPtr<base::Broadcast>()->getOperands();
            checkOpSize(operands, "Broadcast");

            if (needResult)
            {
                setWorkSuccess(task, "Broadcast end");
            }
            else
            {
                setWork(task, "Broadcast end");
            }

            auto root = m_tf.emplace([]() {}).name("root broadcast");
            if (hasParent)
            {
                root.succeed(parent);
            }

            for (auto& operand : operands)
            {
                auto subTask = build(operand, root, false, publisher);
                task.succeed(subTask);
            }
        }
        // Chain
        else if (expression->isChain())
        {
            auto operands = expression->getPtr<base::Chain>()->getOperands();
            checkOpSize(operands, "Chain");

            if (needResult)
            {
                setWorkSuccess(task, "chain end");
            }
            else
            {
                setWork(task, "chain end");
            }

            auto root = m_tf.emplace([]() {}).name("root chain");
            if (hasParent)
            {
                root.succeed(parent);
            }

            auto prevTask = root;
            for (auto& operand : operands)
            {
                prevTask = build(operand, prevTask, false, publisher);
            }
            task.succeed(prevTask);
        }
        // Implication
        else if (expression->isImplication())
        {

            auto operands = expression->getPtr<base::Implication>()->getOperands();
            checkOpSize(operands, "Implication", 2);

            auto root = m_tf.emplace([]() {}).name("root implication");

            if (hasParent)
            {
                root.succeed(parent);
            }

            std::shared_ptr<std::atomic<int>> result = std::make_shared<std::atomic<int>>(SUCCESS);

            auto condTask = build(operands[0], root, true, publisher).name("cond implication");
            auto successTask = build(operands[1], condTask, true, publisher).name("success implication");
            auto failTask = m_tf.emplace(
                                    [result]()
                                    {
                                        result->store(FAILURE);
                                        return SUCCESS; // Always go to success task = task
                                    })
                                .name("fail implication");
            // If condTask has success, execute successTask and if is failure, execute failTask
            condTask.precede(failTask);

            task.name("implication output");
            if (needResult)
            {
                task.work([result]() { return result->load(); });
            }
            else
            {
                task.work([]() {});
            }
            task.succeed(failTask);
            task.succeed(successTask, successTask);
        }
        else if (expression->isOr())
        {
            auto operands = expression->getPtr<base::Or>()->getOperands();
            checkOpSize(operands, "Or");

            auto root = m_tf.emplace([]() { return FAILURE; }).name("root or");
            if (hasParent)
            {
                root.succeed(parent);
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

            auto lastTask = root;
            auto eTask = tf::Task();
            for (auto& operand : operands)
            {
                auto subTask = build(operand, eTask, true, publisher);
                lastTask.precede(successTask, subTask);
                lastTask = subTask;
            }
            lastTask.precede(successTask, task);

            task.name("or output");
            if (needResult)
            {
                task.work([result]() { return result->load(); });
            }
            else
            {
                task.work([]() {});
            }
        }
        // And
        else if (expression->isAnd())
        {
            auto operands = expression->getPtr<base::And>()->getOperands();
            checkOpSize(operands, "And");

            auto root = m_tf.emplace([]() { return SUCCESS; }).name("root and");
            if (hasParent)
            {
                root.succeed(parent);
            }

            std::shared_ptr<std::atomic<int>> result = std::make_shared<std::atomic<int>>(SUCCESS);
            auto failTask = m_tf.emplace(
                                    [result]()
                                    {
                                        result->store(FAILURE);
                                        return SUCCESS;
                                    })
                                .name("fail and")
                                .precede(task);

            auto lastTask = root;
            auto eTask = tf::Task();
            for (auto& operand : operands)
            {
                auto subTask = build(operand, eTask, true, publisher);
                lastTask.precede(subTask, failTask);
                lastTask = subTask;
            }
            lastTask.precede(task, failTask);

            task.name("and output");
            if (needResult)
            {
                task.work([result]() { return result->load(); });
            }
            else
            {
                task.work([]() {});
            }
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

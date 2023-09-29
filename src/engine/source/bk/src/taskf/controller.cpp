#include "controller.hpp"

namespace
{
constexpr int SUCCESS = 0; ///< Success return value (First index in task result)
constexpr int FAILURE = 1; ///< Failure return value (Second index in task result)

using RetWork = std::function<int()>; ///< Definition of a taskflow work that is a conditional task (weak dependency)
using Work = std::function<void()>;      ///< Definition of a taskflow work that is a task (String dependency)

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

/**
 * @brief Create a contional work of a task from a base::EngineOp to a apply it to a base::Event
 * 
 * @param job the base::EngineOp to apply to the base::Event
 * @param eventPtr Pointer to the base::Event
 * @param publisher Publisher function to publish the trace
 * @return Work The work of the task
 */
Work getWork(base::EngineOp&& job, void* eventPtr, bk::taskf::Trace::Publisher publisher)
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
RetWork getRetWork(base::EngineOp&& job, void* eventPtr,  bk::taskf::Trace::Publisher publisher)
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

tf::Task
Controller::build(const base::Expression& expression, tf::Task& parent, bool needResult, Trace::Publisher publisher)
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
            throw std::runtime_error {"Trace already exists"};
        }
        m_traces.emplace(expression->getName(), std::make_unique<Trace>());
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
                prevTask = build(operand, prevTask, false, publisher);
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

            auto condTask = build(operands[0], parent, true, publisher).name("cond implication");
            auto eTask = tf::Task();
            auto successTask = build(operands[1], eTask, true, publisher).name("success implication");
            auto failTask = m_tf.emplace(
                                    [result]()
                                    {
                                        result->store(FAILURE);
                                        return SUCCESS; // Always go to success task = task
                                    })
                                .name("fail implication");
            // If condTask has success, execute successTask and if is failure, execute failTask
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
                auto subTask = build(operand, eTask, true, publisher);
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
                                        return SUCCESS;
                                    })
                                .name("fail and")
                                .precede(task);

            auto lastTask = parent;
            auto eTask = tf::Task();
            for (auto& operand : operands)
            {
                auto subTask = build(operand, eTask, true, publisher);
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
} // namespace bk::taskf
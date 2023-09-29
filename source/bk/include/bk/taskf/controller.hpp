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

/**
 * @copydoc bk::ITrace
 */
class Trace final
    : public ITrace
    , public std::enable_shared_from_this<Trace>
{
private:
    std::string m_name;                                         ///< Name of the trace
    std::unordered_map<Subscription, Subscriber> m_subscribers; ///< subscription id -> subscriber map

    Subscription m_nextSubId {0};                      ///< Next subscription id
    Subscription nextSubId() { return m_nextSubId++; } ///< Get the next subscription id

    std::shared_mutex m_subscribersMutex; ///< Mutex for the subscribers

public:
    ~Trace() = default;

    /**
     * @copydoc bk::ITrace::name
     */
    inline const std::string& name() const override { return m_name; }

    /**
     * @copydoc bk::ITrace::subscribe
     */
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

    /**
     * @copydoc bk::ITrace::unsubscribe
     */
    inline void unsubscribe(Subscription subscription) override
    {
        std::unique_lock lock {m_subscribersMutex};
        m_subscribers.erase(subscription);
    }

    /**
     * @copydoc bk::ITrace::publisher
     */
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

    /**
     * @brief Build a task from an expression
     * 
     * @param expression expression to build
     * @param parent parent task of the task to build (ignore if a empty task)
     * @param needResult if the task needs to return a result
     * @param publisher Publisher function to publish the trace
     * @return tf::Task The task built
     */
    tf::Task build(const base::Expression& expression,
                   tf::Task& parent,
                   bool needResult = false,
                   Trace::Publisher publisher = nullptr);

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

    /**
     * @copydoc bk::IController::ingest
     */
    void ingest(base::Event&& event) override {
        m_event = std::move(event);
        m_executor.run(m_tf).wait();
    }
    
    /**
     * @copydoc bk::IController::ingestGet
     */
    base::Event ingestGet(base::Event&& event) override {
        ingest(std::move(event));
        return std::move(m_event);
    };

    /**
     * @copydoc bk::IController::start
     */
    void start() override {};

    /**
     * @copydoc bk::IController::stop
     */
    void stop() override {};

    /**
     * @copydoc bk::IController::isAviable
     */
    inline bool isAviable() const override { return true; }

    /**
     * @copydoc bk::IController::printGraph
     */
    std::string printGraph() const override { return m_tf.dump(); }

    /**
     * @copydoc bk::IController::getTraceables
     */
    const std::unordered_set<std::string>& getTraceables() const override { return m_traceables; }

    /**
     * @copydoc bk::IController::getTraces
     */
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

    /**
     * @copydoc bk::IController::unsubscribe
     */
    void unsubscribe(const std::string& traceable, ITrace::Subscription subscription) override
    {
        auto it = m_traces.find(traceable);
        if (it == m_traces.end())
        {
            return;
        }

        it->second->unsubscribe(subscription);
    }

};

} // namespace bk::taskf

#endif // BK_TASKF_CONTROLLER_HPP

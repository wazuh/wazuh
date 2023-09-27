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
    std::unordered_map<std::string, std::unique_ptr<Trace>> m_traces; ///< Traces
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

    using RetWork = std::function<size_t()>;
    using Work = std::function<void()>;

    Work getWork(base::EngineOp&& job, void* event, Trace::Publisher publisher)
    {
        return [job = std::move(job), event = *static_cast<base::Event*>(event), publisher]()
        {
            auto res = job(event);
            if (publisher != nullptr)
            {
                publisher(res.trace());
            }
        };
    }

    RetWork getRetWork(base::EngineOp&& job, void* event, Trace::Publisher publisher)
    {
        return [job = std::move(job), event = *static_cast<base::Event*>(event), publisher]() -> size_t
        {
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
            task.name(term->getName()).data(&m_event);
            if (needResult)
            {
                task.work(getRetWork(term->getFn(), task.data(), publisher));
            }
            else
            {
                task.work(getWork(term->getFn(), task.data(), publisher));
            }

            // If not root, add dependency
            if (hasParent)
            {
                task.succeed(parent);
            }
        }
    }

public:
    Controller() = delete;
    Controller(const Controller&) = delete;

    Controller(const base::Expression& expression);

    void ingest(base::Event&& event) override;
    base::Event ingestGet(base::Event&& event) override;

    void start() override;
    void stop() override;

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
};

} // namespace bk::taskf

#endif // BK_TASKF_CONTROLLER_HPP

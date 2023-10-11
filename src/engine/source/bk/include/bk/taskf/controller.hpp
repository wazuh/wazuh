#ifndef _BK_TASKF_CONTROLLER_HPP
#define _BK_TASKF_CONTROLLER_HPP

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

class FakePolicy
{
public:
    base::Expression m_expression;
    std::unordered_set<std::string> m_traceables;

    FakePolicy() = default;
    FakePolicy(base::Expression expression, const std::unordered_set<std::string>& traceables)
        : m_expression(expression)
        , m_traceables(traceables)
    {
    }

    base::Expression expression() const { return m_expression; }
    const std::unordered_set<std::string>& traceables() const { return m_traceables; }
};

class Controller final : public IController
{
private:
    class TracerImpl; ///< Implementation of the trace

    std::unordered_map<std::string, std::shared_ptr<TracerImpl>> m_traces; ///< Traces
    std::unordered_set<std::string> m_traceables;                          ///< Traceables
    base::Expression m_expression;                                         ///< Expression

    tf::Taskflow m_tf;       ///< Taskflow
    tf::Executor m_executor; ///< Executor

    base::Event m_event; ///< Shared event between the tasks

public:
    Controller() = delete;
    Controller(const Controller&) = delete;

    ~Controller() = default;

    // TODO: Update to actual Policy interface
    Controller(const FakePolicy& policy);

    /**
     * @brief Construct a new Controller from an expression and a set of traceables
     *
     * @param expression expression to build
     * @param traceables traceables expressions
     * @param endCallback callback to call when the expression is finished
     */
    Controller(base::Expression expression, std::unordered_set<std::string> traceables, std::function<void()> endCallback = nullptr);

    /**
     * @copydoc bk::IController::ingest
     */
    void ingest(base::Event&& event) override
    {
        m_event = std::move(event);
        m_executor.run(m_tf).wait();
    }

    /**
     * @copydoc bk::IController::ingestGet
     */
    base::Event ingestGet(base::Event&& event) override
    {
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
    base::RespOrError<Subscription> subscribe(const std::string& traceable, const Subscriber& subscriber) override;

    /**
     * @copydoc bk::IController::unsubscribe
     */
    void unsubscribe(const std::string& traceable, Subscription subscription) override;
};

} // namespace bk::taskf

#endif // _BK_TASKF_CONTROLLER_HPP

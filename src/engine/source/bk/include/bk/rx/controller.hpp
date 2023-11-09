#ifndef _BK_RX_CONTROLLER_HPP
#define _BK_RX_CONTROLLER_HPP

#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <rxcpp/rx.hpp>

#include <bk/icontroller.hpp>
#include <expression.hpp>

#include "baseTypes.hpp"

namespace rxcpp
{
using namespace rxcpp;
using namespace rxo;
using namespace rxsub;
using namespace rxu;
} // namespace rxcpp

namespace bk::rx
{

class Controller final : public IController
{
private:
    using RxEvent = std::shared_ptr<base::result::Result<base::Event>>;
    using Observable = rxcpp::observable<RxEvent>;
    class TracerImpl; ///< Implementation of the trace

    std::unordered_map<std::string, std::shared_ptr<TracerImpl>> m_traces; ///< Traces
    std::unordered_set<std::string> m_traceables;                          ///< Traceables
    base::Expression m_expression;                                         ///< Expression

    rxcpp::subjects::subject<RxEvent> m_policySubject;
    rxcpp::subscriber<RxEvent> m_policyInput;
    rxcpp::observable<RxEvent> m_policyOutput;

    bool m_isBuilt; ///< True if the backend is built

public:
    Controller(const Controller&) = delete;

    Controller()
        : m_policyInput(m_policySubject.get_subscriber())
        , m_isBuilt(false)
    {
    }
    ~Controller() = default;

    /**
     * @copydoc bk::IController::build
     */
    void build(base::Expression expression,
               std::unordered_set<std::string> traceables,
               std::function<void()> endCallback) override;

    /**
     * @copydoc bk::IController::build
     */
    void build(base::Expression expression, std::unordered_set<std::string> traceables) override
    {
        build(std::move(expression), std::move(traceables), nullptr);
    };

    /**
     * @copydoc bk::IController::ingest
     */
    void ingest(base::Event&& event) override
    {
        if (!m_isBuilt)
        {
            throw std::runtime_error {"The backend is not built"};
        }
        if (m_policyInput.is_subscribed())
        {
            RxEvent rxEvent =
                std::make_shared<base::result::Result<base::Event>>(base::result::makeSuccess(std::move(event)));
            m_policyInput.on_next(rxEvent);
        }
    }

    /**
     * @copydoc bk::IController::ingestGet
     */
    base::Event ingestGet(base::Event&& event) override
    {
        if (!m_isBuilt)
        {
            throw std::runtime_error {"The backend is not built"};
        }
        if (m_policyInput.is_subscribed())
        {
            RxEvent rxEvent =
                std::make_shared<base::result::Result<base::Event>>(base::result::makeSuccess(std::move(event)));
            m_policyInput.on_next(rxEvent);
            return rxEvent->popPayload();
        }

        return event;
    };

    /**
     * @copydoc bk::IController::start
     */
    void start() override {}

    /**
     * @copydoc bk::IController::stop
     */
    void stop() override
    {
        if (m_isBuilt && m_policyInput.is_subscribed())
        {
            m_policyInput.on_completed();
        }
    };

    /**
     * @copydoc bk::IController::isAviable
     */
    inline bool isAviable() const override { return m_isBuilt; }

    /**
     * @copydoc bk::IController::printGraph
     */
    std::string printGraph() const override { return "TODO"; }

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

} // namespace bk::rx

#endif // _BK_RX_CONTROLLER_HPP

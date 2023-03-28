#ifndef _RX_FACTORY_H
#define _RX_FACTORY_H

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <rxcpp/rx.hpp>

#include "baseTypes.hpp"
#include "builder/policy.hpp"
#include "result.hpp"

namespace rx
{
using namespace rxcpp;
using namespace rxo;
using namespace rxsub;
using namespace rxu;
} // namespace rx

namespace rxbk
{

using RxEvent = std::shared_ptr<base::result::Result<base::Event>>;
using Observable = rx::observable<RxEvent>;

/**
 * @brief Handles subscriptions to trace messages for a given entity.
 *
 * It provides a function to log a trace message, and an output to listen on all trace
 * messages emmitted by said function.
 */
class Tracer
{
private:
    rx::subject<std::string> m_subject;
    rx::observable<std::string> m_output;
    rx::subscriber<std::string> m_subscriber;

public:
    /**
     * @brief Construct a new Tracer object
     *
     */
    Tracer();

    /**
     * @brief Get a function that can be used to log a trace message.
     *
     * This function only will copy/send the message to the output if someone is
     * listening.
     *
     * @param name The name of the entity (Asset) that is logging the trace message.
     * @return std::function<void(const std::string&)> A function that can be used to log
     * a trace message.
     */
    std::function<void(const std::string&)> getTracerFn(std::string name) const;

    /**
     * @brief Subscribe to the output of the tracer.
     *
     * @param s The subscriber to subscribe to the output.
     * @return rx::composite_subscription The subscription to the output.
     */
    rx::composite_subscription subscribe(rx::subscriber<std::string> s);
};

/**
 * @brief Contains the RxCpp backend and exposes it functionality.
 *
 */
class Controller
{
private:
    rx::subjects::subject<RxEvent> m_envSubject;
    rx::subscriber<RxEvent> m_envInput;
    rx::observable<RxEvent> m_envOutput;
    std::unordered_map<std::string, Tracer> m_tracers;

public:
    /**
     * @brief Construct a new Empty Controller object
     *
     */
    Controller();

    /**
     * @brief Ingest an event into the rxcpp pipeline.
     *
     * Calls internal subscriber to forward the event to the rxcpp pipeline only if the
     * subject pipeline is not broken.
     *
     * @param event The event to ingest.
     */
    void ingestEvent(RxEvent&& event);

    /**
     * @brief Complete the rxcpp pipeline.
     *
     * Calls internal subscriber to complete the rxcpp pipeline only if the
     * subject pipeline is not broken.
     */
    void complete();

    /**
     * @brief Get the internal input observable.
     *
     * Return the internal subject's observable, intented to be used as input of the rxcpp
     * pipeline.
     *
     * @return Observable The internal input observable.
     */
    Observable getInternalInput() const;

    /**
     * @brief Get the output observable.
     *
     * Return the output observable, if it is not set, it will return a default
     * initialized observable that is not connected in any manner to the input observable.
     *
     * @return Observable The output observable.
     */
    Observable getOutput() const;

    /**
     * @brief Set the output observable.
     *
     * Set the output observable, output passed should be the result of some
     * transformation from the input observable.
     *
     * @param output The output observable.
     */
    void setOutput(Observable&& output);

    /**
     * @brief Add a tracer to the controller.
     *
     * @param name Name of the tracer
     * @param tracer Tracer object
     * @return std::function<void(const std::string&)> Tracer function of the newly added
     * tracer.
     */
    std::function<void(const std::string&)> addTracer(const std::string& name,
                                                      Tracer&& tracer);

    /**
     * @brief Subscribe to the output of the specified Tracer.
     *
     * @param name Name of the tracer to subscribe to.
     * @param s Subscriber to subscribe to the output.
     * @return rx::composite_subscription The subscription to the output.
     */
    rx::composite_subscription listenOnTrace(const std::string& name,
                                             rxcpp::subscriber<std::string> s);

    /**
     * @brief Subscribe to the output of all Tracers.
     *
     * @param s Subscriber to subscribe to the outputs.
     * @return rx::composite_subscription Aggregated subscription to the outputs.
     */
    rx::composite_subscription listenOnAllTrace(rxcpp::subscriber<std::string> s);

    /**
     * @brief Check if controller has specific tracer.
     *
     * @param name Name of the tracer to check.
     * @return true if controller has tracer.
     * @return false otherwise.
     */
    bool hasTracer(const std::string& name) const;

    /**
     * @brief Get the Tracer object
     *
     * @param name Name of the tracer to get.
     * @return const Tracer& The tracer object.
     * @throw std::out_of_range If the tracer does not exist.
     */
    const Tracer& getTracer(const std::string& name) const;
};

/**
 * @brief Factory method to create a RxCpp pipeline.
 *
 * @param input Input observable to build upon.
 * @param assetNames List of asset names, every expression whose name is in this list will
 * set a tracer for subsequent Terms, when building the pipeline the last idenfied Asset
 * will override the previous one tracer.
 * @param expression The expression to build the pipeline from.
 * @param controller The controller to use for the pipeline, contains the tracers for each
 * Asset.
 * @param tracerFn Current tracer function, if none is passed a default tracer function
 * that does nothing will be used.
 * @return Observable The output observable of the pipeline.
 */
Observable rxFactory(
    const Observable& input,
    const std::unordered_set<std::string>& assetNames,
    base::Expression expression,
    Controller& controller,
    std::function<void(const std::string&)> tracerFn = [](auto) {});

Controller buildRxPipeline(const builder::Policy& environment);

Controller buildRxPipeline(base::Expression expression, const std::unordered_set<std::string>& assetNames);

} // namespace rxbk

#endif // _RX_FACTORY_H

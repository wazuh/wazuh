#ifndef ROUTER_IWORKER_HPP
#define ROUTER_IWORKER_HPP

#include <memory>

#include "irouter.hpp"
#include "itester.hpp"

namespace router
{

class IWorker
{
public:
    using EpsLimit = std::function<bool()>;

    virtual ~IWorker() = default;

    /**
     * @brief Start the worker
     *
     * @param epsCounter The counter to measure the events per second
     */
    virtual void start(const EpsLimit& epsLimit) = 0;

    /**
     * @brief Stop the worker
     */
    virtual void stop() = 0;

    /**
     * @brief Get the router associated with the worker.
     * @return A constant reference to the shared pointer of the router.
     */
    virtual const std::shared_ptr<IRouter>& getRouter() const = 0;

    /**
     * @brief Get the tester associated with the worker.
     * @return A constant reference to the shared pointer of the tester.
     */
    virtual const std::shared_ptr<ITester>& getTester() const = 0;
};

} // namespace router

#endif // ROUTER_IWORKER_HPP

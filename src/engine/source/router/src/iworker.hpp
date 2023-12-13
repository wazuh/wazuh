#ifndef ROUTER_IWORKER_HPP
#define ROUTER_IWORKER_HPP

#include <memory>
#include "irouter.hpp"
#include "itester.hpp"

namespace router {

class IWorker {
public:
    virtual ~IWorker() = default;

    /**
     * @brief Start the worker
     */
    virtual void start() = 0;

    /**
     * @brief Stop the worker
     */
    virtual void stop() = 0;

    virtual const std::shared_ptr<IRouter>& getRouter() const = 0;
    virtual const std::shared_ptr<ITester>& getTester() const = 0;
};

} // namespace router

#endif // ROUTER_IWORKER_HPP

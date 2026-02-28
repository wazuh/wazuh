#ifndef ROUTER_IWORKER_HPP
#define ROUTER_IWORKER_HPP

#include <memory>
#include <type_traits>
#include <stdexcept>

namespace router
{

template<typename T>
class IWorker
{
public:
    virtual ~IWorker() = default;

    /**
     * @brief Start the worker
     *
     */
    virtual void start() = 0;

    /**
     * @brief Stop the worker
     */
    virtual void stop()  = 0;

    /**
     * @brief Get the router or tester associated with the worker.
     * @return A constant reference to the shared pointer of the router.
     */
    virtual std::shared_ptr<T> get() const = 0;
};

} // namespace router

#endif // ROUTER_IWORKER_HPP

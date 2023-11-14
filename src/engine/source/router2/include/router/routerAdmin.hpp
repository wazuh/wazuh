#ifndef _ROUTER2_ROUTERADMIN_HPP
#define _ROUTER2_ROUTERADMIN_HPP

#include <list>
#include <memory>

#include <bk/icontroller.hpp>
#include <store/istore.hpp>
#include <queue/iBlockingConcurrentQueue.hpp>

#include <builder/registry.hpp>
#include <parseEvent.hpp>

#include <router/iapi.hpp>
#include <router/types.hpp>

namespace router
{

// Forward declarations
class Router;

struct Config
{

    std::size_t m_numThreads;
    // TODO Change to weak_ptr
    std::shared_ptr<store::IStore> m_store;
    std::shared_ptr<builder::internals::Registry<builder::internals::Builder>> m_registry;
    std::shared_ptr<bk::IControllerMaker> m_controllerMaker;
    std::shared_ptr<base::queue::iBlockingConcurrentQueue<base::Event>> m_queue;

};

class RouterAdmin : public IRouterAPI
{

private:
    // Config
    Config m_config;

    // State
    std::list<std::shared_ptr<Router>> m_routers;
    std::atomic_bool m_isRunning;       ///< Flag to know if the router is running
    std::vector<std::thread> m_threads; ///< Vector of threads for the router

    void validateConfig();

public:
    ~RouterAdmin() = default;
    RouterAdmin() = delete;

    RouterAdmin(const Config& config);

    /**
     * @brief Start the router
     *
     */
    void start();

    /**
     * @brief Stop the router
     *
     */
    void stop();

    void fastEnqueueEvent(const std::string& eventStr)
    {
        base::Event event;
        try
        {
            event = base::parseEvent::parseWazuhEvent(eventStr);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Error parsing event: '{}' (discarding...)", e.what());
            return;
        }
        m_config.m_queue->push(std::move(event));
    }

    /**************************************************************************
     * IRouterAPI
     *************************************************************************/

    /**
     * @copydoc router::IRouterAPI::postEnvironment
     */
    base::OptError postEnvironment(const EntryPost& environment) override;
};

} // namespace router

#endif // _ROUTER2_ROUTERADMIN_HPP
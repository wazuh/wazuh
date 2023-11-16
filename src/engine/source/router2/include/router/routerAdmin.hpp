#ifndef _ROUTER2_ROUTERADMIN_HPP
#define _ROUTER2_ROUTERADMIN_HPP

#include <list>
#include <memory>
#include <shared_mutex>

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

    std::shared_ptr<base::queue::iBlockingConcurrentQueue<base::Event>> m_queue; // Move to private and fix queue

};

class RouterAdmin : public IRouterAPI
{

private:

    // State
    std::list<std::shared_ptr<Router>> m_routers;
    mutable std::shared_mutex m_bussyMutex; ///< Mutex for updating the router (Only 1 request at a time)
    std::atomic_bool m_isRunning;          ///< Flag to know if the router is running
    std::vector<std::thread> m_threads;    ///< Vector of threads for the router (move router)

    // Internal queue
    struct queue
    {
        std::shared_ptr<base::queue::iBlockingConcurrentQueue<base::Event>> prod;  // Queue for production events
        std::shared_ptr<base::queue::iBlockingConcurrentQueue<base::Event>> testing; // Queue for testing events
    } m_queue;

    void validateConfig(const Config& config);

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

    void pushEvent(const std::string& eventStr)
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
        m_queue.prod->push(std::move(event));
    }

    /**************************************************************************
     * IRouterAPI
     *************************************************************************/

    /**
     * @copydoc router::IRouterAPI::postEnvironment
     */
    base::OptError postEntry(const prod::EntryPost& entry) override;

    /**
     * @copydoc router::IRouterAPI::deleteEnvironment
     */
    base::OptError deleteEntry(const std::string& name) override;

    /**
     * @copydoc router::IRouterAPI::getEnvironment
     */
    base::RespOrError<prod::Entry> getEntry(const std::string& name) const override;

    /**
     * @copydoc router::IRouterAPI::reloadEnvironment
     */
    base::OptError reloadEntry(const std::string& name) override;

    /**
     * @copydoc router::IRouterAPI::ChangeEnvironmentPriority
     */
    base::OptError changeEntryPriority(const std::string& name, size_t priority) override;

    /**
     * @copydoc router::IRouterAPI::getEntries
     */
    std::list<prod::Entry> getEntries() const override;

    /**
     * @copydoc router::IRouterAPI::postEvent
     */
    void postEvent(base::Event&& event) override { m_queue.prod->push(std::move(event)); }

};

} // namespace router

#endif // _ROUTER2_ROUTERADMIN_HPP
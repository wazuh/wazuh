#ifndef _ROUTER_IAPI_HPP
#define _ROUTER_IAPI_HPP

#include <future>
#include <optional>
#include <string>

#include <router/types.hpp>

namespace router
{

/**
 * @brief Interface for the Router API
 *
 */
class IRouterAPI
{
public:
    // Production: Entry
    virtual base::OptError postEntry(const prod::EntryPost& entry) = 0;
    virtual base::OptError deleteEntry(const std::string& name) = 0;
    virtual base::RespOrError<prod::Entry> getEntry(const std::string& name) const = 0;

    virtual base::OptError reloadEntry(const std::string& name) = 0;
    virtual base::OptError changeEntryPriority(const std::string& name, size_t priority) = 0;

    // Production: Table
    virtual std::list<prod::Entry> getEntries() const = 0;

    // Production: Ingest
    virtual void postEvent(base::Event&& event) = 0;
    virtual base::OptError postStrEvent(std::string_view event) = 0;

    // Orchestrator: Change EPS settings
    virtual base::OptError changeEpsSettings(uint eps, uint refreshInterval) = 0;

    // Orchestrator: Get EPS info
    virtual base::RespOrError<std::tuple<uint, uint, bool>> getEpsSettings() const = 0;

    // Orchestrator: Activate/Deactivate EPS counter
    virtual base::OptError activateEpsCounter(bool activate) = 0;
};

class ITesterAPI
{
public:
    // Testing: Entry
    virtual base::OptError postTestEntry(const test::EntryPost& entry) = 0;
    virtual base::OptError deleteTestEntry(const std::string& name) = 0;
    virtual base::RespOrError<test::Entry> getTestEntry(const std::string& name) const = 0;

    virtual base::OptError reloadTestEntry(const std::string& name) = 0;

    // Testing: Table
    virtual std::list<test::Entry> getTestEntries() const = 0;

    // Testing: Ingest Synchronous
    virtual std::future<base::RespOrError<test::Output>> ingestTest(base::Event&& event, const test::Options& opt) = 0;
    virtual std::future<base::RespOrError<test::Output>> ingestTest(std::string_view event,
                                                                    const test::Options& opt) = 0;

    // Testing: Ingest Asynchronous
    virtual base::OptError ingestTest(base::Event&& event,
                                      const test::Options& opt,
                                      std::function<void(base::RespOrError<test::Output>&&)> callbackFn) = 0;
    virtual base::OptError ingestTest(std::string_view event,
                                      const test::Options& opt,
                                      std::function<void(base::RespOrError<test::Output>&&)> callbackFn) = 0;

    // Get the assets of the policy of the entry
    virtual base::RespOrError<std::unordered_set<std::string>> getAssets(const std::string& name) const = 0;

    // Get the timeout of the test of event ingestion (in milliseconds)
    virtual std::size_t getTestTimeout() const = 0;
};
} // namespace router

#endif // _ROUTER_IROUTER_HPP

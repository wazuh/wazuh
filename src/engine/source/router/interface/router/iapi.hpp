#ifndef _ROUTER_IAPI_HPP
#define _ROUTER_IAPI_HPP

#include <future>
#include <optional>
#include <string>

#include <router/types.hpp>

namespace router
{

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

    // Testing: Ingest
    virtual base::RespOrError<std::future<test::Output>> ingestTest(base::Event&& event, const test::Opt& opt) = 0;
    virtual base::RespOrError<std::future<test::Output>> ingestTest(std::string_view event, const test::Opt& opt) = 0;
};
} // namespace router

#endif // _ROUTER_IROUTER_HPP

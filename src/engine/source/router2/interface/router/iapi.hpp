#ifndef _ROUTER2_IAPI_HPP
#define _ROUTER2_IAPI_HPP

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
    // virtual base::OptError postTest(const base::Event& event, const test::Opt& settings) = 0;

};

} // namespace router

#endif // _ROUTER2_IROUTER_HPP

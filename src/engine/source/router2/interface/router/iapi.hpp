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

    // An environment is a session
    virtual base::OptError postEnvironment(const EntryPost& environment) = 0;
    // virtual base::OptError patchEnvironment(const EntryPost& environment) = 0;

    // postTestEnvironment
    // patchTestEnvironment

    // virtual base::OptError deleteEnvironment(const std::string& name) = 0;              // Name or id
    // virtual base::RespOrError<Entry> getEnvironment(const std::string& name) const = 0; // Name or id

    // Table entries
    // virtual base::RespOrError<std::list<Entry>> getEntries() const = 0;

    // Event test
    // virtual base::OptError postTest(const base::Event& event, const test::Opt& settings) = 0;

};

} // namespace router

#endif // _ROUTER2_IROUTER_HPP

#ifndef ROUTER_TEST_INTERNAL_MOCKS_ROUTER_HPP
#define ROUTER_TEST_INTERNAL_MOCKS_ROUTER_HPP

#include <gmock/gmock.h>

#include "irouter.hpp"

namespace router
{
class MockRouter : public router::IRouter
{
public:
    MOCK_METHOD(base::OptError, addEntry, (const ::router::prod::EntryPost& entry, bool ignoreFail), (override));
    MOCK_METHOD(base::OptError, removeEntry, (const std::string& name), (override));
    MOCK_METHOD(base::OptError, rebuildEntry, (const std::string& name), (override));
    MOCK_METHOD(base::OptError, enableEntry, (const std::string& name), (override));
    MOCK_METHOD(base::OptError, changePriority, (const std::string& name, size_t priority), (override));
    MOCK_METHOD(std::list<prod::Entry>, getEntries, (), (const, override));
    MOCK_METHOD(base::RespOrError<prod::Entry>, getEntry, (const std::string& name), (const, override));
    MOCK_METHOD(void, ingest, (base::Event && event), (override));
};

} // namespace router

#endif // ROUTER_TEST_INTERNAL_MOCKS_ROUTER_HPP

#ifndef _API_ROUTER_MOCK_ROUTER_HPP
#define _API_ROUTER_MOCK_ROUTER_HPP

#include <gmock/gmock.h>

#include <router/iapi.hpp>

namespace router::mocks
{

class MockRouterAPI : public ::router::IRouterAPI
{
public:
    MOCK_METHOD(base::OptError, postEntry, (const ::router::prod::EntryPost& entry), (override));
    MOCK_METHOD(base::OptError, deleteEntry, (const std::string& name), (override));
    MOCK_METHOD(base::RespOrError<::router::prod::Entry>, getEntry, (const std::string& name), (const, override));
    MOCK_METHOD(base::OptError, reloadEntry, (const std::string& name), (override));
    MOCK_METHOD(base::OptError, changeEntryPriority, (const std::string& name, size_t priority), (override));
    MOCK_METHOD(std::list<::router::prod::Entry>, getEntries, (), (const, override));
    MOCK_METHOD(void, postEvent, (base::Event && event), (override));
    MOCK_METHOD(base::OptError, postStrEvent, (std::string_view event), (override));
    MOCK_METHOD(base::OptError, changeEpsSettings, (uint eps, uint refreshInterval), (override));
    MOCK_METHOD((base::RespOrError<std::tuple<uint, uint, bool>>), getEpsSettings, (), (const, override));
    MOCK_METHOD(base::OptError, activateEpsCounter, (bool activate), (override));
};

} // namespace router::mocks

#endif // _API_ROUTER_MOCK_ROUTER_HPP

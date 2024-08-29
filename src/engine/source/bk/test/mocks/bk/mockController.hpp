#ifndef _BK_MOCK_CONTROLLER_HPP
#define _BK_MOCK_CONTROLLER_HPP

#include <gmock/gmock.h>

#include <bk/icontroller.hpp>

namespace bk::mocks
{
class MockController : public IController
{
public:
    MOCK_METHOD(void, ingest, (base::Event &&), (override));
    MOCK_METHOD(base::Event, ingestGet, (base::Event &&), (override));
    MOCK_METHOD(bool, isAviable, (), (const, override));
    MOCK_METHOD(void, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(std::string, printGraph, (), (const, override));
    MOCK_METHOD(const std::unordered_set<std::string>&, getTraceables, (), (const, override));
    MOCK_METHOD(base::RespOrError<Subscription>, subscribe, (const std::string&, const Subscriber&), (override));
    MOCK_METHOD(void, unsubscribe, (const std::string&, Subscription), (override));
    MOCK_METHOD(void, unsubscribeAll, (), (override));
};

class MockMakerController : public IControllerMaker
{
public:
    MOCK_METHOD(std::shared_ptr<IController>,
                create,
                (const base::Expression&, const std::unordered_set<std::string>&, const std::function<void()>&),
                (override));
};
} // namespace bk::mocks

#endif // _BK_MOCK_CONTROLLER_HPP

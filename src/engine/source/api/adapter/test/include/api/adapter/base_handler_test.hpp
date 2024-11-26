#ifndef _API_TEST_BASE_HANDLER_TEST_HPP
#define _API_TEST_BASE_HANDLER_TEST_HPP

#include <gtest/gtest.h>

#include <api/adapter/adapter.hpp>
#include <base/behaviour.hpp>
#include <base/logging.hpp>

namespace api::test
{
using ReqGetter = std::function<httplib::Request()>;
using ResGetter = std::function<httplib::Response()>;
template<typename IHandler>
using HandlerGetter = std::function<adapter::RouteHandler(const std::shared_ptr<IHandler>&)>;
template<typename MockHandler>
using Mocker = std::function<void(MockHandler& mock)>;
template<typename IHandler, typename MockHandler>
using Params = std::tuple<ReqGetter, HandlerGetter<IHandler>, ResGetter, Mocker<MockHandler>>;

template<typename IHandler, typename MockHandler>
class BaseHandlerTest : public testing::TestWithParam<Params<IHandler, MockHandler>>
{
protected:
    static_assert(std::is_base_of<IHandler, MockHandler>::value, "MockHandler must inherit from IHandler");

    std::shared_ptr<MockHandler> m_mockHandler;
    std::shared_ptr<IHandler> m_iHandler;

    void SetUp() override
    {
        logging::testInit();

        m_mockHandler = std::make_shared<MockHandler>();
        m_iHandler = m_mockHandler;
    }
};

template<typename IHandler, typename MockHandler>
void handlerTest(ReqGetter& reqGetter,
                 HandlerGetter<IHandler>& handlerGetter,
                 ResGetter& resGetter,
                 const std::shared_ptr<IHandler>& handler,
                 const std::shared_ptr<MockHandler>& mockHandler,
                 Mocker<MockHandler>& mocker)
{
    auto request = reqGetter();
    adapter::RouteHandler routeHandler;
    auto expectedResponse = resGetter();
    ASSERT_NO_THROW(routeHandler = handlerGetter(handler));

    mocker(*mockHandler);
    httplib::Response response;
    ASSERT_NO_THROW(routeHandler(request, response));

    EXPECT_EQ(response.status, expectedResponse.status);
    EXPECT_EQ(response.body, expectedResponse.body);
}

} // namespace api::test

#endif // _API_TEST_BASE_HANDLER_TEST_HPP

// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>

#include <api/metrics/handlers.hpp>

namespace
{
/// Records the options each route is registered with.
class RecordingRegistrar : public httpsrv::IRouteRegistrar
{
public:
    void addRoute(httpsrv::Method method,
                  const std::string& path,
                  httpsrv::RouteHandler,
                  httpsrv::RouteOptions options) override
    {
        methods[path] = method;
        routes[path] = std::move(options);
    }

    std::map<std::string, httpsrv::Method> methods;
    std::map<std::string, httpsrv::RouteOptions> routes;
};

class MetricsRoutesTest : public ::testing::TestWithParam<const char*>
{
protected:
    void SetUp() override
    {
        m_registrar = std::make_shared<RecordingRegistrar>();
        api::metrics::handlers::registerHandlers(nullptr, m_registrar, "wazuh-manager-analysisd", "uptime");
    }

    std::shared_ptr<RecordingRegistrar> m_registrar;
};
} // namespace

TEST(MetricsRoutesRegistrationTest, RegistersTheFourMetricsRoutes)
{
    auto registrar = std::make_shared<RecordingRegistrar>();

    api::metrics::handlers::registerHandlers(nullptr, registrar, "wazuh-manager-analysisd", "uptime");

    EXPECT_EQ(4U, registrar->routes.size());
}

// Reading a metric can wait on the registry lock and on pull getters in other modules, so these routes run on the
// request workers as Control routes: they never hold a transport I/O thread nor the Liveness sessions GET /status
// relies on, and keep their 4 KiB body cap.
TEST_P(MetricsRoutesTest, IsAControlRouteOnTheWorkersCappedAt4KiB)
{
    const std::string path {GetParam()};
    ASSERT_EQ(1U, m_registrar->routes.count(path)) << path << " is not registered";
    const auto& options = m_registrar->routes.at(path);

    EXPECT_EQ(httpsrv::Method::POST, m_registrar->methods.at(path));
    EXPECT_EQ(httpsrv::RouteClass::Control, options.cls);
    EXPECT_FALSE(options.runInline);
    EXPECT_EQ(api::metrics::handlers::METRICS_BODY_CAP, options.maxBodyBytes);
    EXPECT_EQ(4096U, api::metrics::handlers::METRICS_BODY_CAP);
}

INSTANTIATE_TEST_SUITE_P(Routes,
                         MetricsRoutesTest,
                         ::testing::Values("/metrics/enable", "/metrics/get", "/metrics/list", "/metrics/dump"),
                         [](const ::testing::TestParamInfo<const char*>& info)
                         {
                             std::string name {info.param};
                             return name.substr(name.rfind('/') + 1);
                         });

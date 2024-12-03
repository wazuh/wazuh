#include <memory>

#include <gtest/gtest.h>

#include <apiserver/apiServer.hpp>
#include <base/logging.hpp>

#include <conf/apiLoader.hpp>

constexpr auto serverPath {"/run/wazuh-server/config-server.sock"};

TEST(ApiLoader, environmentVariable)
{
    logging::testInit();
    std::shared_ptr<conf::IApiLoader> apiLoader = std::make_shared<conf::ApiLoader>();
    json::Json cnf {};

    // Set the environment variable
    setenv("WAZUH_CONFIG_SKIP_API", "true", 1);
    // Test
    EXPECT_NO_THROW(cnf = (*apiLoader)());
    EXPECT_EQ(cnf, json::Json(R"({})"));
    // Unset the environment variable
    unsetenv("WAZUH_CONFIG_SKIP_API");
}

// Test fixture for the ApiLoader class
// test params: response, status, expected if no exception
class ApiLoaderServerTest : public testing::TestWithParam<std::tuple<std::string, int, std::optional<json::Json>>>
{
protected:
    std::shared_ptr<conf::IApiLoader> m_apiLoader;
    std::shared_ptr<apiserver::ApiServer> m_server;
    std::shared_ptr<std::string> m_response {};
    std::shared_ptr<int> m_status {};

    void addConfigEndpoint()
    {
        m_server->addRoute(apiserver::Method::GET,
                           "/api/v1/config",
                           [this](const httplib::Request& req, httplib::Response& res)
                           {
                               // check params: sections
                               auto sections = req.get_param_value("sections");
                               if (sections != "indexer,engine")
                               {
                                   res.status = 400;
                                   FAIL() << "Invalid sections parameter";
                                   return;
                               }

                               // Set the response code
                               res.status = *(this->m_status);
                               res.set_content(*(this->m_response), "application/json");
                           });
    }

    void SetUp() override
    {
        logging::testInit();
        m_apiLoader = std::make_shared<conf::ApiLoader>();
        m_server = std::make_shared<apiserver::ApiServer>();
        m_status = std::make_shared<int>(200);
        m_response = std::make_shared<std::string>("UNSET RESPONSE");
        unlink(serverPath);
        addConfigEndpoint();
        m_server->start(serverPath);
    }

    void TearDown() override
    {
        m_server->stop();
        m_apiLoader.reset();
        m_server.reset();
        m_status.reset();
        m_response.reset();
        unlink(serverPath);
    }
};

TEST_P(ApiLoaderServerTest, load)
{
    *m_response = std::get<0>(GetParam());
    *m_status = std::get<1>(GetParam());

    if (std::get<2>(GetParam()).has_value())
    {
        json::Json cnf {};
        EXPECT_NO_THROW(cnf = (*m_apiLoader)());
        EXPECT_EQ(cnf, std::get<2>(GetParam()).value());
    }
    else
    {
        EXPECT_THROW((*m_apiLoader)(), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    ApiLoaderServerTestInstantiation,
    ApiLoaderServerTest,
    testing::Values(std::make_tuple(R"({"response": "OK"})", 200, json::Json(R"({"response": "OK"})")),
                    std::make_tuple(R"({"response": "OK"})", 400, std::nullopt),
                    std::make_tuple(R"({"response": "OK"})", 500, std::nullopt),
                    std::make_tuple("INVALID JSON", 200, std::nullopt),
                    std::make_tuple(R"(123)", 200, std::nullopt),
                    std::make_tuple(R"(null)", 200, std::nullopt),
                    std::make_tuple(R"(["array"])", 200, std::nullopt),
                    std::make_tuple(R"("JSON string")", 200, std::nullopt)));

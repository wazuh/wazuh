#include <gtest/gtest.h>
#include <server/engineServer.hpp>
#include <server/endpoint.hpp>
#include <thread>
#include <chrono>

#include <base/logging.hpp>

class MockEndpoint : public engineserver::Endpoint {
public:
    MockEndpoint(const std::string& address, const std::size_t taskQueueSize)
        : Endpoint(address, taskQueueSize) {}

    void bind(std::shared_ptr<uvw::Loop> loop) override {
        m_loop = loop;
    }

    void close() override {
        m_loop.reset();
    }

    bool pause() override {
        return true;
    }

    bool resume() override {
        return true;
    }
};

class EngineServerTest : public testing::Test {
protected:
    void SetUp() override {
        logging::testInit();
        server = std::make_unique<engineserver::EngineServer>();
    }

    void TearDown() override {
        server.reset();
    }

    std::unique_ptr<engineserver::EngineServer> server;
};

TEST_F(EngineServerTest, StartAndRequestStop) {
    std::thread serverThread([this]() {
        server->start();
    });

    // Wait for the server to start and then request to stop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    server->request_stop();

    // Join the server thread to make sure it stops properly
    serverThread.join();
}

TEST_F(EngineServerTest, AddEndpoint) {
    auto endpoint1 = std::make_shared<MockEndpoint>("test_endpoint1", 0);
    ASSERT_NO_THROW(server->addEndpoint("test_endpoint1", endpoint1));

    auto endpoint2 = std::make_shared<MockEndpoint>("test_endpoint2", 0);
    ASSERT_NO_THROW(server->addEndpoint("test_endpoint2", endpoint2));

    auto endpoint3 = std::make_shared<MockEndpoint>("test_endpoint1", 0);
    ASSERT_THROW(server->addEndpoint("test_endpoint1", endpoint3), std::runtime_error);
}

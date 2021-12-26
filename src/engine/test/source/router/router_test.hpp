#include <iostream>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <rxcpp/rx.hpp>
#include <nlohmann/json.hpp>

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

using json = nlohmann::ordered_json;

// Fake Protocol Handlers simulates the behaviour of a protocol handler
// as a router expects it.
template <class F> class FakeProtocolHandler
{
private:

public:

    FakeProtocolHandler<F>(std::function<F(int)> g)
        : generate(g) {};

    // Called when a new subscription is open
    std::function<void()> on_open;

    // Called when a new message is ready
    std::function<void(F f)> on_message;

    // Called when a subscription is closed
    std::function<void()> on_close;

    std::function<F(int)> generate;

    // Run the Fake and generate n events on other thread. Each
    // event is sent to the on_message callback for its processing.
    // A future is returned so tests can wait for its completion.
    // Note that on linux, if the future does not wait, the code
    // in the async block is not executed.
    auto run(int n) {
        return std::async([&, n, this]() {
            for(int i = 0; i < n; i++) {
                this->on_message(generate(i));
            }
            this->on_close();
        });
    };

};


// Fake Builder simulates the behaviour of a builder
// as a router expects it.
template <class F> class FakeBuilder
{
private:
    

public:
    FakeBuilder() {};

    rxcpp::subjects::subject<F> build(std::string id, std::string source) {

        rxcpp::subjects::subject<F> subject;

        auto from = [=](const json j) {
            return j.at("wazuh").at("module").at("name") == source;
        };


        auto res = subject.get_observable().filter(from).subscribe([](const F j) {
            // GTEST_COUT << "test output got an event" << std::endl;
        },
        []() {
            GTEST_COUT << "test output finalized" << std::endl;
        });

        return subject;
    };

};


/**
 * @brief Router Test Suite
 */

#include <algorithm>
#include <chrono>
#include <gtest/gtest.h>
#include <iostream>
#include <rxcpp/rx.hpp>
#include <string>
#include <thread>
#include <vector>

#include <baseTypes.hpp>

#include "router.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

using namespace std;
using namespace rxcpp;
using namespace router;
using document_t = base::Event;
using documents_t = vector<document_t>;

auto createEvent = [](const char * json){
    return std::make_shared<base::EventHandler>(std::make_shared<base::Document>(json));
};
struct FakeServer
{
    explicit FakeServer(const documents_t &documents, bool verbose = false)
        : m_output {observable<>::create<document_t>(
              [=](subscriber<document_t> s)
              {
                  for (document_t document : documents)
                  {
                      if (verbose)
                      {
                          GTEST_COUT << "FakeServer emits " << document->getEvent()->str()
                                     << endl;
                      }
                      s.on_next(document);
                  }
                  s.on_completed();
              })}
    {
    }

    rxcpp::observable<document_t> m_output;
};

// Fake Builder simulates the behaviour of a builder
// as a router expects it.
struct FakeBuilder
{
    using Obs_t = rxcpp::observable<document_t>;
    using Op_t = std::function<Obs_t(Obs_t)>;

    subjects::subject<document_t> m_subj;
    FakeBuilder(bool verbose = false)
    {
        if (verbose)
        {
            this->m_subj.get_observable().subscribe(
                [](auto j)
                { GTEST_COUT << "FakeBuilder got " << j->getEvent()->str() << endl; });
        }
    }

    auto operator()(const std::string &environment)
    {
        auto sub = m_subj.get_subscriber();
        return (struct {
            subscriber<document_t> sub;
            Op_t getLifter()
            {
                return [=](Obs_t p) -> Obs_t
                {
                    p.subscribe(sub);
                    return p;
                };
            }
            std::map<std::string, observable<std::string>> getTraceSinks()
            {
                std::map<std::string, observable<std::string>> fakeSinks;
                fakeSinks["fake_asset"] =
                    observable<>::just<std::string>("test_message");
                return fakeSinks;
            }
        }) {sub};
    }
};

using router_t = Router<FakeBuilder>;

TEST(RouterTest, Initializes)
{
    router_t router(FakeBuilder {});
}

TEST(RouterTest, AddRoute)
{
    router_t router(FakeBuilder {});
    ASSERT_NO_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }));

    ASSERT_EQ(router.routes().size(), 1);
    ASSERT_EQ(router.environments().size(), 1);
    ASSERT_EQ(router.routes().count("test"), 1);
    ASSERT_EQ(router.environments().count("test_env"), 1);
}

TEST(RouterTest, AddDuplicateRoute)
{
    router_t router(FakeBuilder {});
    router.add("test", "test_env", [](document_t d) { return true; });
    ASSERT_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }),
        invalid_argument);
}

TEST(RouterTest, RemoveRoute)
{
    router_t router(FakeBuilder {});
    router.add("test", "test_env", [](document_t d) { return true; });
    ASSERT_NO_THROW(router.remove("test"));
    ASSERT_EQ(router.routes().size(), 0);
    ASSERT_EQ(router.environments().size(), 0);
}

TEST(RouterTest, RemoveNonExistentRoute)
{
    router_t router {FakeBuilder {}};
    ASSERT_THROW(router.remove("test"), invalid_argument);
}

TEST(RouterTest, PassThroughSingleRoute)
{
    documents_t input {
        createEvent(R"({
        "event": 1
    })"),
        createEvent(R"({
        "event": 2
    })"),
        createEvent(R"({
        "event": 3
    })"),
    };
    FakeBuilder builder {true};

    documents_t expected;
    builder.m_subj.get_observable().subscribe([&expected](auto j)
                                              { expected.push_back(j); });

    router_t router {builder};
    router.add("test", "test", [](document_t j) { return true; });

    FakeServer {input, true}.m_output.subscribe(router.input());
    ASSERT_EQ(expected.size(), 3);
    for (auto i = 0; i < 3; ++i)
    {
        ASSERT_EQ(input[i]->getEvent()->str(), expected[i]->getEvent()->str());
    }
}

TEST(RouterTest, SubscribeDebug)
{
    router_t router(FakeBuilder {});
    ASSERT_NO_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }));

    ASSERT_NO_THROW(
        router.subscribeTraceSink("test_env", "fake_asset", [](auto s) {}));
}

TEST(RouterTest, ErrorEnviromentSubscribeDebug)
{
    router_t router(FakeBuilder {});
    ASSERT_NO_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }));

    ASSERT_THROW(
        router.subscribeTraceSink("test_envERROR", "fake_asset", [](auto s) {}),
        runtime_error);
}

TEST(RouterTest, ErrorAssetSubscribeDebug)
{
    router_t router(FakeBuilder {});
    ASSERT_NO_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }));

    ASSERT_THROW(
        router.subscribeTraceSink("test_env", "fake_assetERROR", [](auto s) {}),
        runtime_error);
}

TEST(RouterTest, SubscribeAllDebug)
{
    router_t router(FakeBuilder {});
    ASSERT_NO_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }));

    ASSERT_NO_THROW(router.subscribeAllTraceSinks("test_env", [](auto s) {}));
}

TEST(RouterTest, ErrorSubscribeAllDebug)
{
    router_t router(FakeBuilder {});
    ASSERT_NO_THROW(
        router.add("test", "test_env", [](document_t d) { return true; }));

    ASSERT_THROW(router.subscribeAllTraceSinks("test_envError", [](auto s) {}), runtime_error);
}

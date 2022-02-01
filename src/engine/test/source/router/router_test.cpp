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

#include "json.hpp"
#include "router.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

using namespace std;
using namespace rxcpp;
using namespace router;
using document_t = json::Document;
using documents_t = vector<document_t>;

struct FakeServer
{
    explicit FakeServer(const documents_t & documents, bool verbose = false)
        : m_output{observable<>::create<document_t>(
              [=](subscriber<document_t> s)
              {
                  for (document_t document : documents)
                  {
                      if (verbose)
                      {
                          GTEST_COUT << "FakeServer emits " << document.str() << endl;
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
    subjects::subject<document_t> m_subj;
    FakeBuilder(bool verbose = false)
    {
        if (verbose)
        {
            this->m_subj.get_observable().subscribe([](auto j)
                                                    { GTEST_COUT << "FakeBuilder got " << j.str() << endl; });
        }
    }

    rxcpp::subjects::subject<document_t> operator()(const std::string & environment)
    {
        return this->m_subj;
    }
};

using router_t = Router<FakeBuilder>;

TEST(RouterTest, DefaultConstructor)
{
    ASSERT_NO_THROW(router_t router);
}

TEST(RouterTest, Configures)
{
    router_t router;
    ASSERT_NO_THROW(router.configure(FakeServer{documents_t{}}.m_output, FakeBuilder{}));
}

TEST(RouterTest, ConfiguresConstructor)
{
    ASSERT_NO_THROW(router_t router(FakeServer{documents_t{}}.m_output, FakeBuilder{}));
}

TEST(RouterTest, AddRoute)
{
    router_t router(FakeServer{documents_t{}}.m_output, FakeBuilder{});
    ASSERT_NO_THROW(router.add(
        "test", [](document_t d) { return true; }, "test_env"));

    auto routes{router.routes()};
    auto environments{router.environments()};
    ASSERT_EQ(routes.size(), 1);
    ASSERT_EQ(environments.size(), 1);
    ASSERT_NO_THROW(routes.at("test"));
    ASSERT_NO_THROW(environments.at("test_env"));
}

TEST(RouterTest, AddDuplicateRoute)
{
    router_t router(FakeServer{documents_t{}}.m_output, FakeBuilder{});
    router.add(
        "test", [](document_t d) { return true; }, "test_env");
    ASSERT_THROW(router.add(
                     "test", [](document_t d) { return true; }, "test_env"),
                 invalid_argument);
}

TEST(RouterTest, RemoveRoute)
{
    router_t router(FakeServer{documents_t{}}.m_output, FakeBuilder{});
    router.add(
        "test", [](document_t d) { return true; }, "test_env");
    ASSERT_NO_THROW(router.remove("test"));
    ASSERT_EQ(router.routes().size(), 0);
    ASSERT_EQ(router.environments().size(), 0);
}

TEST(RouterTest, RemoveNonExistentRoute)
{
    router_t router(FakeServer{documents_t{}}.m_output, FakeBuilder{});
    ASSERT_THROW(router.remove("test"), invalid_argument);
}

TEST(RouterTest, PassThroughSingleRoute)
{
    documents_t input{
        document_t(R"({
        "event": 1
    })"),
        document_t(R"({
        "event": 2
    })"),
        document_t(R"({
        "event": 3
    })"),
    };
    FakeBuilder builder(true);

    documents_t expected;
    builder.m_subj.get_observable().subscribe([&expected](auto j) { expected.push_back(j); });

    router_t router(FakeServer{input, true}.m_output, builder);
    router.add(
        "test", [](document_t j) { return true; }, "test");

    ASSERT_EQ(expected.size(), 3);
    for (auto i = 0; i < 3; ++i)
    {
        ASSERT_EQ(input[i].str(), expected[i].str());
    }
}

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>

#include "builder.hpp"
#include "builder_test.hpp"
#include "connectable.hpp"
#include "register.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "
using namespace base;

auto createEvent = [](const char * json){
    return std::make_shared<EventHandler>(std::make_shared<Document>(json));
};

template<class T>
using Op_t = std::function<T(T)>;
template<class T>
using observable = rxcpp::observable<T>;
template<class T>
using Sub_t = rxcpp::subscriber<T>;
template<class T>
using Con_t = builder::internals::Connectable<observable<T>>;

TEST(Builder, EnvironmentSingleDecoder)
{
    builder::internals::registerBuilders();
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    ASSERT_NO_THROW(auto root = builder.build("environment_1"));
}

TEST(Builder, EnvironmentSingleDecoderSingleRule)
{
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_2");
}

TEST(Builder, EnvironmentSingleDecoderSingleRuleSingleFilter)
{
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_3");
}

TEST(Builder, EnvironmentOneofEachAsset)
{
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_4");
}

template<class Value>
void visit(observable<Value> source,
           Con_t<Value> root,
           std::map<Con_t<Value>, std::set<Con_t<Value>>> &edges,
           Sub_t<Value> s)
{
    auto itr = edges.find(root);
    if (itr == edges.end())
    {
        throw std::invalid_argument("Value root is not in the graph");
    }

    // Visit node
    Con_t<Value> node = itr->first;
    if (node.m_inputs.size() == 0)
        node.addInput(source);

    observable<Value> obs = node.connect();

    // Add obs as an input to the childs
    for (Con_t<Value> n : itr->second)
    {
        n.addInput(obs);
    }

    // Visit childs
    for (auto &n : itr->second)
    {
        visit(obs, n, edges, s);
    }
    if (itr->second.size() == 0)
    {
        obs.subscribe(s);
    }
}

TEST(Builder, GraphRulesFilteredOut)
{
    using Sub_t = rxcpp::subscriber<Event>;
    using Con_t = builder::internals::Connectable<Observable>;

    int expected = 2;
    auto source = rxcpp::observable<>::create<Event>(
                      [expected](const Sub_t s)
                      {
                          for (int i = 0; i < expected; i++)
                          {
                              if (i % 2 == 0)
                                  s.on_next(createEvent(R"({"type": "int", "field": "odd",
                                  "value": 0})"));
                              else
                                  s.on_next(createEvent(R"({"type": "int", "field": "even",
                                  "value": 1})"));
                          }
                          s.on_completed();
                      })
                      .publish();

    auto sub = rxcpp::subjects::subject<Event>();

    auto subscriber = rxcpp::make_subscriber<Event>([](Event v) { GTEST_COUT << "Got " << v->getEvent()->str() << std::endl;
    },
                                                      []() { GTEST_COUT << "OnCompleted" << std::endl; });

    builder::Builder<FakeCatalog> b {FakeCatalog()};
    auto env = b("environment_6");
    env.getLifter()(sub.get_observable()).subscribe(subscriber);

    source.subscribe(sub.get_subscriber());
    source.connect();

    std::string expectedContents =
        R"({"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
)";

    // std::cerr << env.print().str() << std::endl;

    std::string file {"/tmp/filepath.txt"};

    std::ifstream ifs(file);
    std::string gotContent((std::istreambuf_iterator<char>(ifs)),
                           (std::istreambuf_iterator<char>()));

    // std::cout << gotContent << std::endl;
    // std::cout << std::endl;
    // std::cout << expectedContents << std::endl;

    std::filesystem::remove(file);
    ASSERT_EQ(expectedContents, gotContent);
}

TEST(Builder, GraphDuplicatedExample)
{
    using Sub_t = rxcpp::subscriber<Event>;
    using Con_t = builder::internals::Connectable<Observable>;

    int expected = 2;
    auto source = rxcpp::observable<>::create<Event>(
                      [expected](const Sub_t s)
                      {
                          for (int i = 0; i < expected; i++)
                          {
                              if (i % 2 == 0)
                                  s.on_next(createEvent(R"({"type": "int", "field": "odd",
                                  "value": 0})"));
                              else
                                  s.on_next(createEvent(R"({"type": "int", "field": "even",
                                  "value": 1})"));
                          }
                          s.on_completed();
                      })
                      .publish();

    auto sub = rxcpp::subjects::subject<Event>();

    auto subscriber = rxcpp::make_subscriber<Event>([](Event v) { GTEST_COUT << "Got " << v->getEvent()->str() << std::endl;
    },
                                                      []() { GTEST_COUT << "OnCompleted" << std::endl; });

    builder::Builder<FakeCatalog> b{FakeCatalog()};
    auto env = b("environment_7");
    env.getLifter()(sub.get_observable()).subscribe(subscriber);

    source.subscribe(sub.get_subscriber());
    source.connect();

    std::string expectedContents =
        R"({"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
)";

    // std::cerr << env.print().str() << std::endl;

    std::string file{"/tmp/filepath.txt"};

    std::ifstream ifs(file);
    std::string gotContent((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    // std::cout << gotContent << std::endl;
    // std::cout << std::endl;
    // std::cout << expectedContents << std::endl;

    std::filesystem::remove(file);
    ASSERT_EQ(expectedContents, gotContent);
}

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"

#include "builder.hpp"
#include "builderTest.hpp"
#include "connectable.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

template <class T> using Op_t = std::function<T(T)>;
template <class T> using Obs_t = rxcpp::observable<T>;
template <class T> using Sub_t = rxcpp::subscriber<T>;
template <class T> using Con_t = builder::internals::Connectable<Obs_t<T>>;

TEST(Builder, EnvironmentSingleDecoder)
{
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_1");
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

template <class Value>
void visit(Obs_t<Value> source, Con_t<Value> root, std::map<Con_t<Value>, std::set<Con_t<Value>>> & edges,
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

    Obs_t<Value> obs = node.connect();

    // Add obs as an input to the childs
    for (Con_t<Value> n : itr->second)
    {
        n.addInput(obs);
    }

    // Visit childs
    for (auto & n : itr->second)
    {
        visit(obs, n, edges, s);
    }
    if (itr->second.size() == 0)
    {
        obs.subscribe(s);
    }
}

TEST(RXCPP, DecoderManualConnectExample)
{
    using Event_t = json::Document;
    using Obs_t = rxcpp::observable<json::Document>;
    using Sub_t = rxcpp::subscriber<json::Document>;
    using Con_t = builder::internals::Connectable<Obs_t>;

    int expected = 2;
    auto source = rxcpp::observable<>::create<Event_t>(
                      [expected](const Sub_t s)
                      {
                          for (int i = 0; i < expected; i++)
                          {
                              if (i % 2 == 0)
                                  s.on_next(Event_t(R"({"type": "int", "field": "odd", "value": 0})"));
                              else
                                  s.on_next(Event_t(R"({"type": "int", "field": "even", "value": 1})"));
                          }
                          s.on_completed();
                      })
                      .publish();

    auto sub = rxcpp::subjects::subject<Event_t>();

    auto subscriber = rxcpp::make_subscriber<Event_t>([](Event_t v) { GTEST_COUT << "Got " << v.str() << std::endl; },
                                                      []() { GTEST_COUT << "OnCompleted" << std::endl; });

    builder::Builder<FakeCatalog> b{FakeCatalog()};
    auto env = b.build("environment_6");
    std::map<Con_t, std::set<Con_t>> res = env.get();
    visit<Event_t>(sub.get_observable(), Con_t("DECODERS_INPUT"), res, subscriber);

    source.subscribe(sub.get_subscriber());
    source.connect();

    std::string expectedContents =
        R"({"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3"}
{"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3"}
{"type":"int","field":"odd","value":0,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field1":"new_dec_value1","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3"}
{"type":"int","field":"even","value":1,"new_dec_field0":"new_dec_value0","new_dec_field2":"new_dec_value2","new_dec_field3":"new_dec_value3","new_rule_field":"new_rule_value"}
)";

    std::cerr << env.print().str() << std::endl;

    std::string file{"/tmp/filepath.txt"};

    std::ifstream ifs(file);
    std::string gotContent((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    std::filesystem::remove(file);
    ASSERT_TRUE(expectedContents == gotContent);
}

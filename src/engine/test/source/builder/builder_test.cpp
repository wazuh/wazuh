#include "builder_test.hpp"
#include "builder.hpp"
#include "connectable.hpp"
#include "rxcpp/rx.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <string>
#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

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

TEST(Builder, EnvSingleDecoderProcess)
{
    using Event_t = json::Document;

    using Subs_t = rxcpp::subscriber<Event_t>;
    using Obs_t = rxcpp::observable<Event_t>;

    using Con_t = builder::internals::Connectable;
    using pCon_t = std::shared_ptr<Con_t>;

    using Node_t = graph::Node<Con_t>;
    using pNode_t = std::shared_ptr<Node_t>;

    int expected{1};

    // Prepare fake server/router
    auto source = std::make_shared<Con_t>("source");
    source->set(rxcpp::observable<>::create<Event_t>(
        [expected](const Subs_t s)
        {
            for (int i = 0; i < expected; i++)
            {
                s.on_next(Event_t(R"({"field": "value" })"));
            }
            s.on_completed();
        }));
    auto pSourceNode = std::make_shared<Node_t>(source);

    // Prepare the fake output
    auto destination = std::make_shared<Con_t>("destination");
    auto pDestNode = std::make_shared<Node_t>(destination);

    int got{0};

    // Build graph
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_1");
    graph::visitLeaves<Con_t>(root, [&](auto leaf) { leaf->connect(pDestNode); });

    destination->output().subscribe(
        [&](const auto & e)
        {
            got++;
            GTEST_COUT << e.str() << std::endl;
        },
        [](const std::exception_ptr & e)
        {
            try
            {
                std::rethrow_exception(e);
            }
            catch (const std::exception & ex)
            {
                GTEST_COUT << "OnError: " << ex.what() << std::endl;
            }
        },
        []() { GTEST_COUT << "completed" << std::endl; });

    pSourceNode->connect(root);

    ASSERT_EQ(expected * 2, got);
}

std::string EachOfOneDiagraph = R"(digraph G {
decoder_input -> decoder_input;
decoder_input -> decoder_0;
decoder_0 -> filter_0;
filter_0 -> decoder_output;
decoder_output -> output_input;
output_input -> output_0;
output_0 -> output_output;
output_output -> destination;
decoder_output -> rule_input;
rule_input -> rule_0;
rule_0 -> rule_output;
rule_output -> output_input;
}
)";

TEST(Builder, EnvironmentOneofEachAssetProcess)
{
    using Event_t = json::Document;

    using Subs_t = rxcpp::subscriber<Event_t>;
    using Obs_t = rxcpp::observable<Event_t>;

    using Con_t = builder::internals::Connectable;
    using pCon_t = std::shared_ptr<Con_t>;

    using Node_t = graph::Node<Con_t>;
    using pNode_t = std::shared_ptr<Node_t>;

    int expected{1};

    // Prepare fake server/router
    auto source = std::make_shared<Con_t>("source");
    source->set(rxcpp::observable<>::create<Event_t>(
        [expected](const Subs_t s)
        {
            for (int i = 0; i < expected; i++)
            {
                s.on_next(Event_t(R"({"field": "value" })"));
            }
            s.on_completed();
        }));
    auto pSourceNode = std::make_shared<Node_t>(source);

    // Prepare the fake output
    auto destination = std::make_shared<Con_t>("destination");
    auto pDestNode = std::make_shared<Node_t>(destination);

    int got{0};

    // Build graph
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_4");
    graph::visitLeaves<Con_t>(root, [&](auto leaf) { leaf->connect(pDestNode); });

    destination->output().subscribe(
        [&](const auto & e)
        {
            got++;
            GTEST_COUT << e.str() << std::endl;
        },
        [](const std::exception_ptr & e)
        {
            try
            {
                std::rethrow_exception(e);
            }
            catch (const std::exception & ex)
            {
                GTEST_COUT << "OnError: " << ex.what() << std::endl;
            }
        },
        []() { GTEST_COUT << "completed" << std::endl; });

    pSourceNode->connect(root);
    auto diagraph = graph::print<Con_t>(root);
    ASSERT_EQ(expected * 2, got);
    ASSERT_EQ(diagraph.str(), EachOfOneDiagraph);
}

TEST(Builder, Environment5)
{
    using Event_t = json::Document;

    using Subs_t = rxcpp::subscriber<Event_t>;
    using Obs_t = rxcpp::observable<Event_t>;

    using Con_t = builder::internals::Connectable;
    using pCon_t = std::shared_ptr<Con_t>;

    using Node_t = graph::Node<Con_t>;
    using pNode_t = std::shared_ptr<Node_t>;

    int expected{1};

    // Prepare fake server/router
    auto source = std::make_shared<Con_t>("source");
    source->set(rxcpp::observable<>::create<Event_t>(
        [expected](const Subs_t s)
        {
            for (int i = 0; i < expected; i++)
            {
                s.on_next(Event_t(R"({"field": "value" })"));
            }
            s.on_completed();
        }));
    auto pSourceNode = std::make_shared<Node_t>(source);

    // Prepare the fake output
    auto destination = std::make_shared<Con_t>("destination");
    auto pDestNode = std::make_shared<Node_t>(destination);

    int got{0};

    // Build graph
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_5");
    graph::visitLeaves<Con_t>(root, [&](auto leaf) { leaf->connect(pDestNode); });

    destination->output().subscribe(
        [&](const auto & e)
        {
            got++;
            GTEST_COUT << e.str() << std::endl;
        },
        [](const std::exception_ptr & e)
        {
            try
            {
                std::rethrow_exception(e);
            }
            catch (const std::exception & ex)
            {
                GTEST_COUT << "OnError: " << ex.what() << std::endl;
            }
        },
        []() { GTEST_COUT << "completed" << std::endl; });

    pSourceNode->connect(root);
    auto diagraph = graph::print<Con_t>(root);
    ASSERT_EQ(expected * 2, got);
}

TEST(Builder, Environment6)
{
    using Event_t = json::Document;

    using Subs_t = rxcpp::subscriber<Event_t>;
    using Obs_t = rxcpp::observable<Event_t>;

    using Con_t = builder::internals::Connectable;
    using pCon_t = std::shared_ptr<Con_t>;

    using Node_t = graph::Node<Con_t>;
    using pNode_t = std::shared_ptr<Node_t>;

    int expected{1};

    // Prepare fake server/router
    auto source = std::make_shared<Con_t>("source");
    source->set(rxcpp::observable<>::create<Event_t>(
        [expected](const Subs_t s)
        {
            for (int i = 0; i < expected; i++)
            {
                s.on_next(Event_t(R"({"field": "value" })"));
            }
            s.on_completed();
        }));
    auto pSourceNode = std::make_shared<Node_t>(source);

    // Prepare the fake output
    auto destination = std::make_shared<Con_t>("destination");
    auto pDestNode = std::make_shared<Node_t>(destination);

    int got{0};

    // Build graph
    FakeCatalog fCatalog;
    auto builder = builder::Builder<FakeCatalog>(fCatalog);
    auto root = builder.build("environment_6");
    graph::visitLeaves<Con_t>(root, [&](auto leaf) { leaf->connect(pDestNode); });

    destination->output().subscribe(
        [&](const auto & e)
        {
            got++;
            GTEST_COUT << e.str() << std::endl;
        },
        [](const std::exception_ptr & e)
        {
            try
            {
                std::rethrow_exception(e);
            }
            catch (const std::exception & ex)
            {
                GTEST_COUT << "OnError: " << ex.what() << std::endl;
            }
        },
        []() { GTEST_COUT << "completed" << std::endl; });

    pSourceNode->connect(root);
    auto diagraph = graph::print<Con_t>(root);
    GTEST_COUT << diagraph.str() << std::endl;
    ASSERT_EQ(expected * 4, got);
}

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <math.h>

#include "rxcpp/rx-test.hpp"
#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"
#include "graph_test.hpp"
#include "graph/graph.hpp"

TEST(Graph, Node)
{
    using con_t = fakeConnectable<int>;
    using node_t = Graph::Node<con_t>;

    auto n{node_t(std::make_shared<con_t>(con_t("decoder")))};
}

TEST(Graph, Connect_two_nodes)
{
    using con_t = fakeConnectable<int>;
    using node_t = Graph::Node<con_t>;

    auto pf1{std::make_shared<con_t>(con_t("decoder_1"))};
    auto pf2{std::make_shared<con_t>(con_t("decoder_2"))};

    auto pNode1{std::make_shared<node_t>(node_t(pf1))};
    auto pNode2{std::make_shared<node_t>(node_t(pf2))};

    pNode1->connect(pNode2);
    ASSERT_EQ(pNode1->adjacents().size(), 1);
}

TEST(Graph, Connect_two_nodes_loop)
{
    using con_t = fakeConnectable<int>;
    using node_t = Graph::Node<con_t>;

    auto pf1{std::make_shared<con_t>(con_t("decoder_1"))};
    auto pf2{std::make_shared<con_t>(con_t("decoder_2"))};

    auto pNode1{std::make_shared<node_t>(node_t(pf1))};
    auto pNode2{std::make_shared<node_t>(node_t(pf2))};

    pNode1->connect(pNode2);
    EXPECT_THROW(pNode2->connect(pNode1), std::invalid_argument);
}

TEST(Graph, Connect_two_check_result)
{
    using con_t = fakeConnectable<int>;
    using node_t = Graph::Node<con_t>;

    int expected(10);
    auto source = rxcpp::observable<>::create<int>([expected](rxcpp::subscriber<int> s)
                                                   {
        for(int i=0; i<expected; i++) {
            s.on_next(i);
        }
        s.on_completed(); });

    auto pf1{std::make_shared<con_t>(con_t("decoder_1"))};
    auto pf2{std::make_shared<con_t>(con_t("decoder_2"))};

    pf1->map([](int i)
             { return i * 2; })
        .filter([](int i)
                { return i % 2 == 0; });

    auto pNode1{std::make_shared<node_t>(node_t(pf1))};
    auto pNode2{std::make_shared<node_t>(node_t(pf2))};

    pNode1->connect(pNode2);

    int got(0);

    pNode2->observable().subscribe(
        [&got](const int &i)
        { got++; },
        [&got]()
        { GTEST_COUT << "completed " << got << std::endl; });

    source.subscribe(pNode1->subscriber());
    ASSERT_EQ(expected, got);
}

TEST(Graph, Connect_a_simple_graph_to_result)
{
    using con_t = fakeConnectable<int>;
    using node_t = Graph::Node<con_t>;

    int expected(10);
    auto source = rxcpp::observable<>::create<int>([expected](rxcpp::subscriber<int> s)
                                                   {
        for(int i=0; i<expected; i++) {
            s.on_next(i);
        }
        s.on_completed(); });

    auto plus{con_t("plus").map([](int i)
                                { return i + 1; })};
    auto pPlusDec{std::make_shared<con_t>(plus)};

    auto odd{con_t("odd").filter([](int i)
                                 { return i % 2 == 0; })
                 .map([](int i)
                      { return i * 2; })};
    auto pOddDec{std::make_shared<con_t>(odd)};

    auto even{con_t("even").filter([](int i)
                                   { return i % 2 != 0; })
                  .map([](int i)
                       { return i * 3; })};
    auto pEvenDec{std::make_shared<con_t>(even)};

    auto minus{con_t("minus").map([](int i)
                                  { return i - 1; })};
    auto pMinusDec{std::make_shared<con_t>(minus)};

    auto pOddNode{std::make_shared<node_t>(node_t(pOddDec))};
    auto pEvenNode{std::make_shared<node_t>(node_t(pEvenDec))};
    auto pPlusNode{std::make_shared<node_t>(node_t(pPlusDec))};
    auto pMinusNode{std::make_shared<node_t>(node_t(pMinusDec))};

    // graph
    //               odd
    //             |     |
    // source -> plus    minus  -> result
    //             |     |
    //              even

    pPlusNode->connect(pOddNode);
    pPlusNode->connect(pEvenNode);
    pOddNode->connect(pMinusNode);
    pEvenNode->connect(pMinusNode);

    int got(0);

    pMinusNode->observable().subscribe(
        [&got](const int &i)
        { got++; },
        [&got]()
        { GTEST_COUT << "completed " << got << std::endl; });

    source.subscribe(pPlusNode->subscriber());
    ASSERT_EQ(expected, got);
}

TEST(Graph, Connect_all_leaves)
{
    using con_t = fakeConnectable<int>;
    using node_t = Graph::Node<con_t>;

    int expected(10);
    auto source = rxcpp::observable<>::create<int>([expected](rxcpp::subscriber<int> s)
                                                   {
        for(int i=0; i<expected; i++) {
            s.on_next(i);
        }
        s.on_completed(); });

    auto plus{con_t("plus").map([](int i)
                                { return i + 1; })};
    auto plusPtr{std::make_shared<con_t>(plus)};

    auto oddPtr(std::make_shared<con_t>(con_t("odd").filter([](int i)
                                                            { return i % 2 == 0; })
                                            .map([](int i)
                                                 { return i * 2; })));

    auto even{con_t("even").filter([](int i)
                                   { return i % 2 != 0; })
                  .map([](int i)
                       { return i * 3; })};
    auto evenPtr{std::make_shared<con_t>(even)};

    auto output{std::make_shared<con_t>(con_t("output"))};

    auto nodeOdd{std::make_shared<node_t>(node_t(oddPtr))};
    auto nodeEven{std::make_shared<node_t>(node_t(evenPtr))};
    auto nodePlus{std::make_shared<node_t>(node_t(plusPtr))};
    auto nodeOutput{std::make_shared<node_t>(node_t(output))};

    // graph
    //               odd
    //             |     |
    // source -> plus     output
    //             |     |
    //              even

    nodePlus->connect(nodeOdd);
    nodePlus->connect(nodeEven);

    int got(0);

    nodePlus->visitLeaves([nodeOutput](auto leaf)
                          { leaf->connect(nodeOutput); });

    nodeOutput->observable().subscribe(
        [&got](const int &i)
        { got++; },
        [&got]()
        { GTEST_COUT << "completed " << got << std::endl; });

    source.subscribe(nodePlus->subscriber());
    ASSERT_EQ(expected, got);
}

TEST(Graph, Connect_a_big_graph)
{
    using con_t = fakeConnectable<std::string>;
    using node_t = Graph::Node<con_t>;
    using pNode_t = std::shared_ptr<node_t>;

    int expected(10000);

    auto source = rxcpp::observable<>::create<std::string>(
        [expected](rxcpp::subscriber<std::string> s)
        {
            for (int i = 0; i < expected; i++)
            {
                s.on_next("source->");
            }
            s.on_completed();
        });

    // binary tree
    auto heigh = 10;
    auto size = std::pow(2, heigh + 1) - 1;
    auto last = std::pow(2, heigh) - 1;

    std::vector<pNode_t> nodes;

    for (int i = 0; i < size; i++)
    {
        auto pNode{std::make_shared<node_t>(
            std::make_shared<con_t>(
                con_t("decoder " + std::to_string(i))
                    .filter([i](std::string s)
                            { return i % 2 == 0; })
                    .map([i](std::string s)
                         { return s + "decoder " + std::to_string(i) + "-->"; })))};

        nodes.push_back(pNode);
    }

    for (int i = 0; i < last; i++)
    {
        nodes[i]->connect(nodes[2 * i + 1]);
        nodes[i]->connect(nodes[2 * i + 2]);
    }

    auto pOutputNode{std::make_shared<node_t>(node_t(std::make_shared<con_t>(con_t("output"))))};

    nodes[0]->visitLeaves([&pOutputNode](auto leaf)
                          { leaf->connect(pOutputNode); });

    int got(0);

    pOutputNode->observable().subscribe(
        [&got](std::string s)
        { got++; },
        [](std::exception_ptr &e) {},
        [&got, expected, heigh]()
        { GTEST_COUT << "Completed! "<< got <<  " through " << 2*heigh+1 << " decoders" << std::endl; ASSERT_EQ(expected, got); });

    source.subscribe(nodes[0]->subscriber());
}

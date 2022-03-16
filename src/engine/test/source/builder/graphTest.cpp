#include <algorithm>
#include <chrono>
#include <iostream>
#include <math.h>
#include <string>
#include <thread>

#include "graph.hpp"
#include "graphTest.hpp"
#include "rxcpp/rx-test.hpp"
#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"

TEST(Graph, Node)
{
    /*
    using con_t = fakeConnectable<int>;
    using node_t = graph::Node<con_t>;

    auto n{node_t(std::make_shared<con_t>(con_t("decoder")))};
    */
    GTEST_SKIP();
}

TEST(Graph, Connect_two_nodes)
{
    GTEST_SKIP();

    // using con_t = fakeConnectable<int>;
    // using node_t = graph::Node<con_t>;

    // auto pf1{std::make_shared<con_t>(con_t("decoder_1"))};
    // auto pf2{std::make_shared<con_t>(con_t("decoder_2"))};

    // auto pNode1{std::make_shared<node_t>(node_t(pf1))};
    // auto pNode2{std::make_shared<node_t>(node_t(pf2))};

    // pNode1->connect(pNode2);
    // ASSERT_EQ(pNode1->adjacents().size(), 1);
}

TEST(Graph, CanVisitLoops)
{
//     using con_t = fakeConnectable<int>;
//     using node_t = graph::Node<con_t>;

//     auto pf1{std::make_shared<con_t>("decoder_1")};
//     auto pf2{std::make_shared<con_t>("decoder_2")};
//     auto pf3{std::make_shared<con_t>("decoder_3")};
//     auto pf4{std::make_shared<con_t>("decoder_4")};

//     auto pNode1{std::make_shared<node_t>(pf1)};
//     auto pNode2{std::make_shared<node_t>(pf2)};
//     auto pNode3{std::make_shared<node_t>(pf3)};
//     auto pNode4{std::make_shared<node_t>(pf4)};

//     pNode1->connect(pNode2);
//     pNode2->connect(pNode3);
//     pNode3->connect(pNode4);
//     pNode1->connect(pNode1);
//     graph::visit<con_t>(pNode1,
//                         [](auto n) { GTEST_COUT << n.first->name() << " --> " << n.second->name() << std::endl; });
//     graph::visitLeaves<con_t>(pNode1, [](auto n) { GTEST_COUT << n->name() << std::endl; });
    GTEST_SKIP();
}

TEST(Graph, Connect_two_check_result)
{
    GTEST_SKIP();
    // using con_t = fakeConnectable<int>;
    // using node_t = graph::Node<con_t>;

    // int expected(10);
    // auto source = rxcpp::observable<>::create<int>(
    //     [expected](rxcpp::subscriber<int> s)
    //     {
    //         for (int i = 0; i < expected; i++)
    //         {
    //             s.on_next(i);
    //         }
    //         s.on_completed();
    //     });

    // auto pf1{std::make_shared<con_t>(con_t("decoder_1"))};
    // auto pf2{std::make_shared<con_t>(con_t("decoder_2"))};

    // pf1->set(pf1->output().map([](int i) { return i * 2; }).filter([](int i) { return i % 2 == 0; }));

    // auto pNode1{std::make_shared<node_t>(node_t(pf1))};
    // auto pNode2{std::make_shared<node_t>(node_t(pf2))};

    // pNode1->connect(pNode2);

    // int got(0);

    // pNode2->m_value->output().subscribe([&got](const int & i) { got++; },
    //                                     [&got]() { GTEST_COUT << "completed " << got << std::endl; });

    // source.subscribe(pNode1->m_value->input());
    // ASSERT_EQ(expected, got);
}

TEST(Graph, Connect_a_simple_graph_to_result)
{
    // using con_t = fakeConnectable<int>;
    // using node_t = graph::Node<con_t>;

    // int expected(10);
    // auto source = rxcpp::observable<>::create<int>(
    //     [expected](rxcpp::subscriber<int> s)
    //     {
    //         for (int i = 0; i < expected; i++)
    //         {
    //             s.on_next(i);
    //         }
    //         s.on_completed();
    //     });

    // auto plus{con_t("plus")};
    // plus.set(plus.output().map([](int i) { return i + 1; }));
    // auto pPlusDec{std::make_shared<con_t>(plus)};

    // auto odd{con_t("odd")};
    // odd.set(odd.output().filter([](int i) { return i % 2 == 0; }).map([](int i) { return i * 2; }));

    // auto pOddDec{std::make_shared<con_t>(odd)};

    // auto even{con_t("even")};
    // even.set(even.output().filter([](int i) { return i % 2 != 0; }).map([](int i) { return i * 3; }));

    // auto pEvenDec{std::make_shared<con_t>(even)};

    // auto minus{con_t("minus")};
    // minus.set(minus.output().map([](int i) { return i - 1; }));

    // auto pMinusDec{std::make_shared<con_t>(minus)};

    // auto pOddNode{std::make_shared<node_t>(node_t(pOddDec))};
    // auto pEvenNode{std::make_shared<node_t>(node_t(pEvenDec))};
    // auto pPlusNode{std::make_shared<node_t>(node_t(pPlusDec))};
    // auto pMinusNode{std::make_shared<node_t>(node_t(pMinusDec))};

    GTEST_SKIP();
    // graph
    //               odd
    //             |     |
    // source -> plus    minus  -> result
    //             |     |
    //              even



    // pPlusNode->connect(pOddNode);
    // pPlusNode->connect(pEvenNode);
    // pOddNode->connect(pMinusNode);
    // pEvenNode->connect(pMinusNode);

    // int got(0);

    // pMinusNode->m_value->output().subscribe([&got](const int & i) { got++; },
    //                                         [&got]() { GTEST_COUT << "completed " << got << std::endl; });

    // source.subscribe(pPlusNode->m_value->input());
    // ASSERT_EQ(expected, got);
}

TEST(Graph, Connect_all_leaves)
{
    GTEST_SKIP();
    // using con_t = fakeConnectable<int>;
    // using node_t = graph::Node<con_t>;

    // int expected(10);
    // auto source = rxcpp::observable<>::create<int>(
    //     [expected](rxcpp::subscriber<int> s)
    //     {
    //         for (int i = 0; i < expected; i++)
    //         {
    //             s.on_next(i);
    //         }
    //         s.on_completed();
    //     });

    // auto plus{con_t("plus")};
    // plus.set(plus.output().map([](int i) { return i + 1; }));
    // auto plusPtr{std::make_shared<con_t>(plus)};

    // auto odd{con_t("odd")};
    // odd.set(odd.output().filter([](int i) { return i % 2 == 0; }).map([](int i) { return i * 2; }));
    // auto oddPtr(std::make_shared<con_t>(odd));

    // auto even{con_t("even")};
    // even.set(even.output().filter([](int i) { return i % 2 != 0; }).map([](int i) { return i * 3; }));

    // auto evenPtr{std::make_shared<con_t>(even)};

    // auto output{std::make_shared<con_t>(con_t("output"))};

    // auto nodeOdd{std::make_shared<node_t>(node_t(oddPtr))};
    // auto nodeEven{std::make_shared<node_t>(node_t(evenPtr))};
    // auto nodePlus{std::make_shared<node_t>(node_t(plusPtr))};
    // auto nodeOutput{std::make_shared<node_t>(node_t(output))};

    // graph
    //               odd
    //             |     |
    // source -> plus     output
    //             |     |
    //              even

    // nodePlus->connect(nodeOdd);
    // nodePlus->connect(nodeEven);

    // int got(0);

    // graph::visitLeaves<con_t>(nodePlus, [nodeOutput](auto leaf) { leaf->connect(nodeOutput); });

    // nodeOutput->m_value->output().subscribe([&got](const int & i) { got++; },
    //                                         [&got]() { GTEST_COUT << "completed " << got << std::endl; });

    // source.subscribe(nodePlus->m_value->input());
    // ASSERT_EQ(expected, got);
}

TEST(Graph, Connect_a_big_graph)
{
    // using con_t = fakeConnectable<std::string>;
    // using node_t = graph::Node<con_t>;
    // using pNode_t = std::shared_ptr<node_t>;

    // int expected(10000);

    // auto source = rxcpp::observable<>::create<std::string>(
    //     [expected](rxcpp::subscriber<std::string> s)
    //     {
    //         for (int i = 0; i < expected; i++)
    //         {
    //             s.on_next("source->");
    //         }
    //         s.on_completed();
    //     });

    // // binary tree
    // auto heigh = 10;
    // auto size = std::pow(2, heigh + 1) - 1;
    // auto last = std::pow(2, heigh) - 1;

    // std::vector<pNode_t> nodes;

    // for (int i = 0; i < size; i++)
    // {
    //     auto dec = con_t("decoder " + std::to_string(i));
    //     dec.set(dec.output()
    //                 .filter([i](std::string s) { return i % 2 == 0; })
    //                 .map([i](std::string s) { return s + "decoder " + std::to_string(i) + "-->"; }));
    //     auto pNode{std::make_shared<node_t>(std::make_shared<con_t>(dec))};

    //     nodes.push_back(pNode);
    // }

    // for (int i = 0; i < last; i++)
    // {
    //     nodes[i]->connect(nodes[2 * i + 1]);
    //     nodes[i]->connect(nodes[2 * i + 2]);
    // }

    // auto pOutputNode{std::make_shared<node_t>(node_t(std::make_shared<con_t>(con_t("output"))))};

    // graph::visitLeaves<con_t>(nodes[0], [&pOutputNode](auto leaf) { leaf->connect(pOutputNode); });

    // int got(0);

    // pOutputNode->m_value->output().subscribe([&got](std::string s) { got++; }, [](std::exception_ptr & e) {},
    //                                          [&got, expected, heigh]()
    //                                          {
    //                                              GTEST_COUT << "Completed! " << got << " through " << 2 * heigh + 1
    //                                                         << " decoders" << std::endl;
    //                                              ASSERT_EQ(expected, got);
    //                                          });

    // source.subscribe(nodes[0]->m_value->input());
    GTEST_SKIP();
}

TEST(Graph, Group_by)
{
    // using con_t = fakeConnectable<std::string>;
    // using node_t = graph::Node<con_t>;

    // int expected(10);

    // auto source = rxcpp::observable<>::create<std::string>(
    //     [expected](rxcpp::subscriber<std::string> s)
    //     {
    //         for (int i = 0; i < expected; i++)
    //         {
    //             s.on_next(std::to_string(i));
    //         }
    //         s.on_completed();
    //     });

    // auto plus{con_t("plus")};
    // plus.set(plus.output().map([](std::string i) { return i; }));
    // auto pPlusDec{std::make_shared<con_t>(plus)};

    // auto odd{con_t("odd")};
    // odd.set(odd.output().map([](std::string i) { return i + " odd"; }));

    // auto pOddDec{std::make_shared<con_t>(odd)};

    // auto even{con_t("even")};
    // even.set(even.output().map([](std::string i) { return i + " even"; }));

    // auto pEvenDec{std::make_shared<con_t>(even)};

    // auto minus{con_t("minus")};
    // minus.set(minus.output().map([](std::string i) { return i; }));

    // auto pMinusDec{std::make_shared<con_t>(minus)};

    // auto pOddNode{std::make_shared<node_t>(node_t(pOddDec))};
    // auto pEvenNode{std::make_shared<node_t>(node_t(pEvenDec))};
    // auto pPlusNode{std::make_shared<node_t>(node_t(pPlusDec))};
    // auto pMinusNode{std::make_shared<node_t>(node_t(pMinusDec))};

    // graph
    //               odd
    //             |     |
    // source -> plus    minus  -> result
    //             |     |
    //              even

    // pPlusNode->connect(pOddNode);
    // pPlusNode->connect(pEvenNode);
    // pOddNode->connect(pMinusNode);
    // pEvenNode->connect(pMinusNode);

    // int got(0);

    // pMinusNode->m_value->output().subscribe(
    //     [&got](const std::string & i)
    //     {
    //         got++;
    //         GTEST_COUT << i << std::endl;
    //     },
    //     [&got]() { GTEST_COUT << "completed " << got << std::endl; });

    // source.subscribe(pPlusNode->m_value->input());
    // ASSERT_EQ(expected * 2, got);
    GTEST_SKIP();
}

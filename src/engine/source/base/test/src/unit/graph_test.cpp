#include "graph.hpp"
#include <gtest/gtest.h>

#include <unordered_set>

TEST(GraphTest, DefaultConstructor)
{
    auto initialize = []()
    {
        return Graph<std::string, int>();
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_EQ(graph.rootId(), "");
    ASSERT_TRUE(graph.empty());
}

TEST(GraphTest, Constructor)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_EQ(graph.rootId(), "root");
    ASSERT_EQ(graph.node("root"), 2);
}

TEST(GraphTest, SetRoot)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_EQ(graph.rootId(), "root");
    ASSERT_EQ(graph.node("root"), 2);
    ASSERT_NO_THROW(graph.setRoot("newRoot", 3));
    ASSERT_EQ(graph.rootId(), "newRoot");
    ASSERT_EQ(graph.node("newRoot"), 3);
    ASSERT_FALSE(graph.hasNode("root"));
    ASSERT_FALSE(graph.hasChildren("root"));

    graph = Graph<std::string, int> {};
    ASSERT_NO_THROW(graph.setRoot("newRoot", 3));
    ASSERT_EQ(graph.rootId(), "newRoot");
    ASSERT_EQ(graph.node("newRoot"), 3);
}

TEST(GraphTest, AddNode)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_NO_THROW(graph.addNode("newNode", 3));
    ASSERT_TRUE(graph.hasNode("newNode"));
    ASSERT_EQ(graph.node("newNode"), 3);
    ASSERT_FALSE(graph.hasChildren("newNode"));

    ASSERT_THROW(graph.addNode("newNode", 3), std::runtime_error);
}

TEST(GraphTest, AddEdge)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_NO_THROW(graph.addNode("newNode", 3));
    ASSERT_NO_THROW(graph.addEdge("root", "newNode"));
    ASSERT_TRUE(graph.hasChildren("root"));
    ASSERT_EQ(graph.children("root").size(), 1);
    ASSERT_EQ(graph.children("root").front(), "newNode");

    ASSERT_THROW(graph.addEdge("root", "newNode"), std::runtime_error);
}

TEST(GraphTest, InjectNode)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_NO_THROW(graph.addNode("newNode", 3));
    ASSERT_NO_THROW(graph.addEdge("root", "newNode"));

    ASSERT_NO_THROW(graph.injectNode("newNode2", 4, "root"));
    ASSERT_TRUE(graph.hasNode("newNode2"));
    ASSERT_TRUE(graph.hasChildren("root"));
    ASSERT_EQ(graph.children("root").size(), 1);
    ASSERT_EQ(graph.children("root").front(), "newNode2");
    ASSERT_TRUE(graph.hasChildren("newNode2"));
    ASSERT_EQ(graph.children("newNode2").size(), 1);
    ASSERT_EQ(graph.children("newNode2").front(), "newNode");

    ASSERT_THROW(graph.injectNode("newNode2", 4, "root"), std::runtime_error);
}

TEST(GraphTest, GetRootId)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_EQ(graph.rootId(), "root");
}

TEST(GraphTest, GetNode)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_EQ(graph.node("root"), 2);

    ASSERT_THROW(graph.node("newNode"), std::runtime_error);
}

TEST(GraphTest, GetChildren)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_NO_THROW(graph.addNode("newNode", 3));
    ASSERT_NO_THROW(graph.addEdge("root", "newNode"));
    ASSERT_EQ(graph.children("root").size(), 1);
    ASSERT_EQ(graph.children("root").front(), "newNode");

    ASSERT_THROW(graph.children("newNode"), std::runtime_error);
}

TEST(GraphTest, HasNode)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_TRUE(graph.hasNode("root"));
    ASSERT_FALSE(graph.hasNode("newNode"));
}

TEST(GraphTest, HasChildren)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_FALSE(graph.hasChildren("root"));
    ASSERT_NO_THROW(graph.addNode("newNode", 3));
    ASSERT_NO_THROW(graph.addEdge("root", "newNode"));
    ASSERT_TRUE(graph.hasChildren("root"));
    ASSERT_FALSE(graph.hasChildren("newNode"));
}

TEST(GraphTest, Empty)
{
    auto emptyInitialize = []()
    {
        return Graph<std::string, int>();
    };
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 2);
    };

    ASSERT_NO_THROW(emptyInitialize());
    auto emptyGraph = emptyInitialize();
    ASSERT_TRUE(emptyGraph.empty());
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();
    ASSERT_FALSE(graph.empty());
}

TEST(GraphTest, VisitPreOrder)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 0);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();

    // Generate a random graph, with graph depth of 11 and max number of 5 children per
    // node. Remember added nodes to check that the visit function is called on them and
    // in the correct order.
    std::unordered_set<std::string> addedNodes = {"root"};
    std::vector<std::string> expectedNodes = {"root"};
    std::vector<std::string> expectedLeafNodes;
    for (int i = 1; i < 11; ++i)
    {
        std::string nodeName = "node" + std::to_string(i);
        graph.addNode(nodeName, i);
        addedNodes.insert(nodeName);
    }
    std::string prev = "root";
    for (auto i = 1; i < 11; ++i)
    {
        auto nodeName = "node" + std::to_string(i);
        graph.addEdge(prev, nodeName);
        prev = nodeName;
        expectedNodes.push_back(nodeName);

        // Add random number of children to the node.
        auto numChildren = std::rand() % 5;
        for (auto j = 0; j < numChildren; ++j)
        {
            auto childName = nodeName + "." + std::to_string(j);
            graph.addNode(childName, j);
            graph.addEdge(nodeName, childName);
            addedNodes.insert(childName);
            expectedNodes.push_back(childName);
            expectedLeafNodes.push_back(childName);
        }
    }

    // Check visit function
    auto it = expectedNodes.begin();
    auto visitor = [&](const std::string& nodeId, const int& nodeValue)
    {
        ASSERT_TRUE(addedNodes.find(nodeId) != addedNodes.end());
        ASSERT_EQ(nodeId, *it);
        ++it;
    };
    ASSERT_NO_THROW(graph.visit(visitor));

    it = expectedLeafNodes.begin();
    auto visitorLeaf = [&](const std::string& nodeId, const int& nodeValue)
    {
        ASSERT_TRUE(addedNodes.find(nodeId) != addedNodes.end());
        ASSERT_EQ(nodeId, *it);
        ++it;
    };
    ASSERT_NO_THROW(graph.visitLeaves(visitorLeaf));
}

TEST(GraphTest, GetGraphStr)
{
    auto initialize = []()
    {
        return Graph<std::string, int>("root", 0);
    };
    ASSERT_NO_THROW(initialize());
    auto graph = initialize();

    for (int i = 1; i < 11; ++i)
    {
        std::string nodeName = "node" + std::to_string(i);
        graph.addNode(nodeName, i);
    }
    std::string prev = "root";
    for (auto i = 1; i < 11; ++i)
    {
        auto nodeName = "node" + std::to_string(i);
        graph.addEdge(prev, nodeName);
        prev = nodeName;

        for (auto j = 0; j < 5; ++j)
        {
            auto childName = nodeName + "." + std::to_string(j);
            graph.addNode(childName, j);
            graph.addEdge(nodeName, childName);
        }
    }

    auto expected = R"(strict digraph G {
"root" -> "node1"
"node1" -> "node1.0"
"node1" -> "node1.1"
"node1" -> "node1.2"
"node1" -> "node1.3"
"node1" -> "node1.4"
"node1" -> "node2"
"node2" -> "node2.0"
"node2" -> "node2.1"
"node2" -> "node2.2"
"node2" -> "node2.3"
"node2" -> "node2.4"
"node2" -> "node3"
"node3" -> "node3.0"
"node3" -> "node3.1"
"node3" -> "node3.2"
"node3" -> "node3.3"
"node3" -> "node3.4"
"node3" -> "node4"
"node4" -> "node4.0"
"node4" -> "node4.1"
"node4" -> "node4.2"
"node4" -> "node4.3"
"node4" -> "node4.4"
"node4" -> "node5"
"node5" -> "node5.0"
"node5" -> "node5.1"
"node5" -> "node5.2"
"node5" -> "node5.3"
"node5" -> "node5.4"
"node5" -> "node6"
"node6" -> "node6.0"
"node6" -> "node6.1"
"node6" -> "node6.2"
"node6" -> "node6.3"
"node6" -> "node6.4"
"node6" -> "node7"
"node7" -> "node7.0"
"node7" -> "node7.1"
"node7" -> "node7.2"
"node7" -> "node7.3"
"node7" -> "node7.4"
"node7" -> "node8"
"node8" -> "node8.0"
"node8" -> "node8.1"
"node8" -> "node8.2"
"node8" -> "node8.3"
"node8" -> "node8.4"
"node8" -> "node9"
"node9" -> "node9.0"
"node9" -> "node9.1"
"node9" -> "node9.2"
"node9" -> "node9.3"
"node9" -> "node9.4"
"node9" -> "node10"
"node10" -> "node10.0"
"node10" -> "node10.1"
"node10" -> "node10.2"
"node10" -> "node10.3"
"node10" -> "node10.4"
}
)";
    std::string got;
    ASSERT_NO_THROW(got = graph.getGraphStr());
    ASSERT_EQ(got, expected);
}

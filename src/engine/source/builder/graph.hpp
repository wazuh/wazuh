#ifndef _GRAPH_H
#define _GRAPH_H

#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

#include "builderTypes.hpp"

namespace builder::internals
{
/**
 * @brief Implements the graph and its algorithms. Used as a helper to build
 * the RXCPP observable graph based on our assets definitions.
 *
 * It can contain almost any value. We use it with Connectables.
 *
 * @tparam Value type of the value it will contain.
 */
class Graph
{
public:
    /**
     * @brief Map of connectables, with connectable name as key and connectable as value
     *
     */
    std::map<std::string, types::ConnectableT> m_nodes;

    /**
     * @brief graph edes are represented by the connection between a
     * Connectable name and its set of Connectable child names.
     */
    std::map<std::string, std::set<std::string>> m_edges;

    /**
     * @brief Adds a value to the graph, and initializes its child set
     * as empty.
     *
     * @param a Value
     */
    void addNode(types::ConnectableT conn)
    {
        if (m_nodes.count(conn.m_name) != 0)
        {
            throw std::invalid_argument("Connectable " + conn.m_name + " is already in the graph");
        }
        if (m_edges.count(conn.m_name) != 0)
        {
            throw std::invalid_argument("Connectable " + conn.m_name + " is already in the graph edges");
        }

        m_nodes[conn.m_name] = conn;
        m_edges[conn.m_name] = {};
    }

    /**
     * @brief Adds all edges described by Connectable's parents and stablishes
     * input and output of the graph, all connectables that don't have parents are
     * connected to root, all connectables that don't have childs are connected to
     * end.
     *
     * @param root Name of connectable root for this graph
     * @param end  Name of output connectable for this graph
     */
    void addParentEdges(std::string root, std::string end)
    {
        addNode(types::ConnectableT(root));
        addNode(types::ConnectableT(end));
        for (auto & node : m_nodes)
        {
            if (node.first == root || node.first == end)
                continue;

            if (node.second.m_parents.size() == 0)
            {
                node.second.m_parents.push_back(root);
                addEdge(root, node.first);
            }
            else
            {
                for (auto & parent : node.second.m_parents)
                {
                    addEdge(parent, node.first);
                }
            }
        }

        // Add leaves to end
        for (auto & node : m_edges)
        {
            if (node.first == root || node.first == end)
                continue;

            if (node.second.size() == 0)
            {
                m_nodes[end].m_parents.push_back(node.first);
                addEdge(node.first, end);
            }
        }
    }

    /**
     * @brief Joins other graph under this graph, concretly `otherInputNode` under `thisOutputNode`.
     *
     * Does not modify neither graph, returns a new one.
     *
     * @param other
     * @param thisOutputNode
     * @param otherInputNode
     * @return Graph
     */
    Graph join(const Graph & other, std::string thisOutputNode, std::string otherInputNode) const
    {
        if (m_nodes.count(thisOutputNode) == 0)
        {
            throw std::invalid_argument("Connectable " + thisOutputNode + " is not in the graph");
        }
        if (other.m_nodes.count(otherInputNode) == 0)
        {
            throw std::invalid_argument("Connectable " + otherInputNode + " is not in the graph to be joined");
        }

        Graph g;
        std::map<std::string, types::ConnectableT> auxObs{m_nodes};
        g.m_nodes.merge(auxObs);
        auxObs = other.m_nodes;
        g.m_nodes.merge(auxObs);
        std::map<std::string, std::set<std::string>> auxEdges{m_edges};
        g.m_edges.merge(auxEdges);
        auxEdges = other.m_edges;
        g.m_edges.merge(auxEdges);

        g.addEdge(thisOutputNode, otherInputNode);
        g.m_nodes[otherInputNode].m_parents.push_back(thisOutputNode);

        return g;
    }

    /**
     * @brief Injects other graph nodes on this graph, edges on other graph are ignored.
     *
     * Does not modify neither graph, returns a new one.
     *
     * @param other
     * @return Graph
     */
    Graph inject(const Graph & other) const
    {
        Graph g;
        std::map<std::string, types::ConnectableT> auxObs{m_nodes};
        g.m_nodes.merge(auxObs);
        std::map<std::string, std::set<std::string>> auxEdges{m_edges};
        g.m_edges.merge(auxEdges);

        for (auto & node : other.m_nodes)
        {
            for (auto & p : node.second.m_parents)
            {
                g.addNode(node.second);
                g.injectEdge(p, node.first);
            }
        }

        return g;
    }

    /**
     * @brief Injects value b between a and its childs, so b becomes the parent
     * of a's childs and the only child of a.
     *
     * @param a parent to inject into
     * @param b node to become the only child of a
     */
    void injectEdge(std::string a, std::string b)
    {
        if (m_nodes.count(a) == 0)
        {
            throw std::invalid_argument("Connectable " + a + " is not in the graph");
        }
        if (m_nodes.count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b + " is not in the graph");
        }

        for (auto & child : m_edges[a])
        {
            auto it = std::find(m_nodes[child].m_parents.begin(), m_nodes[child].m_parents.end(), a);
            m_nodes[child].m_parents.erase(it);
            m_nodes[child].m_parents.push_back(b);
        }

        m_edges[b].merge(m_edges[a]);
        m_edges[a] = {b};
    }

    /**
     * @brief Removes b from the child set of a.
     *
     * @param a Value
     * @param b Value
     */
    void removeEdge(std::string a, std::string b)
    {
        if (m_nodes.count(a) == 0)
        {
            throw std::invalid_argument("Connectable " + a + " is not in the graph");
        }
        if (m_nodes.count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b + " is not in the graph");
        }

        if (m_edges[a].count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b + " is not child of " + a);
        }

        m_edges[a].erase(b);
    }

    /**
     * @brief Add b to the child set of a.
     *
     * @param a
     * @param b
     */
    void addEdge(std::string a, std::string b)
    {
        if (m_nodes.count(a) == 0)
        {
            throw std::invalid_argument("Connectable " + a + " is not in the graph");
        }
        if (m_nodes.count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b + " is not in the graph");
        }

        // TODO: Maybe we just try to insert and not throw
        if (!m_edges[a].insert(b).second)
        {
            throw std::invalid_argument("Connectable " + b + " is already a child of " + a);
        }
    }

    /**
     * @brief visit all nodes of the graph only once. The visitor function
     * will receive a pair with the value and a set of its childs.
     *
     * @param fn
     */
    void visit(std::function<void(types::ConnectableT)> fn)
    {
        for (auto & n : m_nodes)
        {
            fn(n.second);
        }
    }

    /**
     * @brief Visit all graph leaves, which are the nodes with empty child sets.
     *
     * @param fn visitor function will receive only a Value
     */
    void leaves(std::function<void(types::ConnectableT)> fn) const
    {
        for (auto & n : m_edges)
        {
            if (n.second.size() == 0)
                fn(n.first);
        }
    }

    /**
     * @brief Returnss a stringstream with a graphviz representation of this
     * graph.
     *
     * @return std::stringstream
     */
    std::stringstream print() const
    {
        std::stringstream diagraph;
        diagraph << "digraph G {" << std::endl;
        for (auto & n : m_edges)
        {
            if (n.second.size() > 0)
                for (auto & c : n.second)
                    diagraph << n.first << " -> " << c << ";" << std::endl;
            else
                diagraph << n.first << " -> void;" << std::endl;
        }
        diagraph << "}" << std::endl;
        return diagraph;
    }

    /**
     * @brief Same as m_node operator [].
     *
     * @param node
     * @return types::ConnectableT&
     */
    types::ConnectableT & operator[](std::string node)
    {
        return m_nodes[node];
    }
};
} // namespace builder::internals

#endif // _GRAPH_H

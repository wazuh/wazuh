#ifndef _GRAPH_H
#define _GRAPH_H

#include <vector>

namespace _graph
{

/**
 * @brief Implements the graph and its algorithms. Used as a helper to build
 * the RXCPP observable graph based on our assets definitions. 
 * 
 * It can contain almost any value. We use it with Connectables.
 * 
 * @tparam Value type of the value it will contain.
 */
template <class Value> class Graph
{
private:
    /**
     * @brief graph edes are represented by the connection between a
     * Value and its set of Value childs.
     */
    std::map<Value, std::set<Value>> m_edges;

public:

    /**
     * @brief Adds a value to the graph, and initializes its child set
     * as empty.
     * 
     * @param a Value 
     */
    void addNode(Value a)
    {
        std::set<Value> v;
        m_edges.insert(std::make_pair(a, v));
    }

    auto get()
    {
        return m_edges;
    }

    /**
     * @brief Injects value b between a and its childs, so b becomes the parent
     * of a's childs and the only child of a.
     * 
     * @param a 
     * @param b 
     */
    void injectEdge(Value a, Value b)
    {
        auto ita = m_edges.find(a);
        if (ita == m_edges.end())
        {
            throw std::invalid_argument("Value a is not in the graph");
        }
        auto itb = m_edges.find(b);
        if (itb == m_edges.end())
        {
            throw std::invalid_argument("Value b is not in the graph");
        }

        std::for_each(ita->second.begin(), ita->second.end(), [&](auto c) { add_edge(itb->first, c); });
        ita->second = std::set<Value>();
        add_edge(ita->first, itb->first);
    }

    /**
     * @brief Removes b from the child set of a.
     * 
     * @param a Value
     * @param b Value
     */
    void removeEdge(Value a, Value b)
    {
        auto ita = m_edges.find(a);
        if (ita == m_edges.end())
        {
            throw std::invalid_argument("Value a is not in the graph");
        }
        auto itb = ita->second.find(b);
        if (itb == ita->second.end())
        {
            throw std::invalid_argument("Value b is not in the value a adjacent list");
        }
        ita->second.erase(*itb);
    }

    /**
     * @brief Add b to the child set of b.
     * 
     * @param a 
     * @param b 
     */
    void addEdge(Value a, Value b)
    {
        auto ita = m_edges.find(a);
        if (ita == m_edges.end())
        {
            throw std::invalid_argument("Value a is not in the graph");
        }
        auto itb = m_edges.find(b);
        if (itb == m_edges.end())
        {
            throw std::invalid_argument("Value b is not in the graph");
        }

        ita->second.insert(itb->first);
    }

    /**
     * @brief visit all nodes of the graph only once. The visitor function
     * will receive a pair with the value and a set of its childs.
     * 
     * @param fn 
     */
    void visit(std::function<void(std::pair<Value, std::set<Value>>)> fn) const
    {
        for (auto & n : m_edges)
        {
            fn(n);
        }
    }

    /**
     * @brief Visit all graph leaves, which are the nodes with empty child sets.
     * 
     * @param fn visitor function will receive only a Value
     */
    void leaves(std::function<void(Value)> fn) const
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
};

} // namespace _graph

#endif

#ifndef _GRAPH_H
#define _GRAPH_H

#include <sstream>
#include <stack>
#include <string>
#include <unordered_map>
#include <unordered_set>

template<typename K, typename T>
class Graph
{
public:
    K m_root;
    std::unordered_map<K, T> m_nodes;
    std::unordered_map<K, std::vector<K>> m_edges;

public:
    Graph() = default;

    Graph(K rootId, T root)
        : m_root {rootId}
        , m_nodes {std::make_pair(rootId, root)}
    {
    }

    void addNode(K id, T node)
    {
        m_nodes.insert(std::make_pair(id, node));
        if (m_edges.find(id) == m_edges.end())
        {
            m_edges.insert(std::make_pair(id, std::vector<K>()));
        }
    }

    void addEdge(K from, K to)
    {
        if (m_edges.find(from) == m_edges.end())
        {
            m_edges.insert(std::make_pair(from, std::vector {{to}}));
        }
        else
        {
            m_edges[from].push_back(to);
        }
    }

    void injectNode(K id, T node, K parent)
    {
        addNode(id, node);
        for (auto& child : m_edges[parent])
        {
            addEdge(id, child);
        }
        m_edges[parent].clear();
        m_edges[parent].push_back(id);
    }

    const K& root() const
    {
        return m_root;
    }

    const T& node(K id) const
    {
        return m_nodes.at(id);
    }

    bool hasNode(K id) const
    {
        return m_nodes.find(id) != m_nodes.end();
    }

    // visit pre-order
    void visit(const std::function<void(const K&, const T&)>& visitor)
    {
        std::stack<std::string> stack;
        stack.push(m_root);

        while (!stack.empty())
        {
            auto id = stack.top();
            stack.pop();

            visitor(id, m_nodes.at(id));

            for (auto& edge : m_edges.at(id))
            {
                stack.push(edge);
            }
        }
    }

    void visitLeafs(const std::function<void(const K&, const T&)>& visitor)
    {
        std::stack<std::string> stack;
        stack.push(m_root);

        while (!stack.empty())
        {
            auto id = stack.top();
            stack.pop();

            if (m_edges.at(id).empty())
            {
                visitor(id, m_nodes.at(id));
            }
            else
            {
                for (auto& edge : m_edges.at(id))
                {
                    stack.push(edge);
                }
            }
        }
    }

    // Graphivz
    std::string getGraphStr() const
    {
        std::stringstream ss;
        ss << "strict digraph G {\n";

        auto visit = [&ss, this](const std::string& id, auto& visitRef) -> void
        {
            if (m_edges.find(id) != m_edges.end())
            {
                for (auto& edge : m_edges.at(id))
                {
                    ss << fmt::format("{} -> {}\n", id, edge);
                    visitRef(edge, visitRef);
                }
            }
        };

        visit(m_root, visit);
        ss << "}\n";
        return ss.str();
    }
};

#endif // _GRAPH_H

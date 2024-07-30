#ifndef _GRAPH_H
#define _GRAPH_H

#include <functional>
#include <queue>
#include <sstream>
#include <stack>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

/**
 * @brief Simple graph class.
 *
 * @tparam K Type of the key for the graph's nodes.
 * @tparam T Type of the value for the graph's nodes.
 */
template<typename K, typename T>
class Graph
{
private:
    K m_root;
    std::unordered_map<K, T> m_nodes;

    void _addNode(K key, T&& value)
    {
        if (m_nodes.end() != m_nodes.find(key))
        {
            throw std::runtime_error(fmt::format("Engine base graph: Node \"{}\" already exists.", key));
        }
        m_nodes[key] = std::move(value);
    }

    void _addEdge(K from, K to)
    {
        if (m_edges.end() == m_edges.find(from))
        {
            m_edges[from] = std::vector<K> {};
            m_edges[from].push_back(to);
        }
        else
        {
            if (m_edges[from].end() != std::find(m_edges[from].begin(), m_edges[from].end(), to))
            {
                throw std::runtime_error(
                    fmt::format("Engine base graph: Edge \"{}\" -> \"{}\" already exists.", from, to));
            }
            else
            {
                m_edges[from].push_back(to);
            }
        }
    }

    void _deleteNode(K key)
    {
        if (m_nodes.end() == m_nodes.find(key))
        {
            throw std::runtime_error(fmt::format("Engine base graph: Node \"{}\" does not exist.", key));
        }
        m_nodes.erase(key);
        m_edges.erase(key);
    }

    void _preOrder(K key, std::function<void(const K&, const T&)> visitor) const
    {
        visitor(key, m_nodes.at(key));
        if (hasChildren(key))
        {
            for (auto child : children(key))
            {
                _preOrder(child, visitor);
            }
        }
    }

public:
    // TODO: Change to private
    std::unordered_map<K, std::vector<K>> m_edges;
    /**
     * @brief Construct a new Graph empty object
     *
     */
    Graph() = default;

    /**
     * @brief Construct a new Graph object
     *
     * @param rootId Root node id.
     * @param root Root node value.
     */
    Graph(K rootId, T root)
        : m_root {rootId}
        , m_nodes {std::make_pair(rootId, root)}
    {
    }

    /**
     * @brief Set the root node.
     *
     * @return K Root node id.
     */
    void setRoot(K rootId, T rootValue)
    {
        if (m_nodes.end() != m_nodes.find(m_root))
        {
            _deleteNode(m_root);
        }
        m_root = rootId;
        _addNode(rootId, std::move(rootValue));
    }

    /**
     * @brief Add node to graph.
     *
     * @param id Node id.
     * @param node Node value.
     */
    void addNode(K id, T node) { _addNode(id, std::move(node)); }

    /**
     * @brief Add directed edge to graph.
     *
     * @param from Node id.
     * @param to Node id.
     */
    void addEdge(K from, K to) { _addEdge(from, to); }

    /**
     * @brief Inject node in graph.
     *
     * When injecting a node (id, node) in the graph under parent, all children of parent
     * will be added as children of the new node, and the parent will have the new node as
     * child.
     *
     * @param id Injected node id.
     * @param node Injected node value.
     * @param parent Parent node id.
     */
    void injectNode(K id, T node, K parent)
    {
        _addNode(id, std::move(node));
        for (auto& child : m_edges[parent])
        {
            _addEdge(id, child);
        }
        m_edges[parent].clear();
        _addEdge(parent, id);
    }

    /**
     * @brief Get the root node id.
     *
     * @return const K& Root node id.
     */
    const K& rootId() const { return m_root; }

    /**
     * @brief Get the node value.
     *
     * @param id Id of the node.
     * @return const T& Value of the node.
     */
    const T& node(K id) const
    {
        if (m_nodes.end() == m_nodes.find(id))
        {
            throw std::runtime_error(fmt::format("Engine base graph: Node \"{}\" does not exist.", id));
        }
        return m_nodes.at(id);
    }

    /**
     * @brief Get the node children.
     *
     * @param id Id of the node.
     * @return const std::vector<K>& Children of the node.
     *
     * @throws std::runtime_error if node does not have children.
     */
    const std::vector<K>& children(K id) const
    {
        if (m_edges.end() == m_edges.find(id))
        {
            throw std::runtime_error(fmt::format("Engine base graph: Node \"{}\" has no children.", id));
        }
        return m_edges.at(id);
    }

    /**
     * @brief Get the edges map.
     *
     * @return const std::unordered_map<K, std::vector<K>>&
     */
    const std::unordered_map<K, std::vector<K>>& edges() const { return m_edges; }

    /**
     * @brief Get the nodes map.
     *
     * @return const std::unordered_map<K, T>&
     */
    const std::unordered_map<K, T>& nodes() const { return m_nodes; }

    /**
     * @brief Check if node exists.
     *
     * @param id Node id.
     * @return true If node exists.
     * @return false If node does not exist.
     */
    bool hasNode(K id) const { return m_nodes.find(id) != m_nodes.end(); }

    /**
     * @brief Check if node has children.
     *
     * @param id Node id.
     * @return true If node has children.
     * @return false If node does not have children.
     */
    bool hasChildren(K id) const
    {
        auto it = m_edges.find(id);
        return it != m_edges.end() && !it->second.empty();
    }

    /**
     * @brief Check if graph is empty.
     *
     * @return true
     * @return false
     */
    bool empty() const { return m_nodes.empty(); }

    /**
     * @brief Preorder traversal of the graph.
     *
     * @warning If multiple parent nodes have the same child, the child will be visited
     * multiple times.
     *
     * @param visitor Function to call for each node.
     */
    void visit(const std::function<void(const K&, const T&)>& visitor)
    {
        // preorder traversal
        _preOrder(m_root, visitor);
    }

    /**
     * @brief Preorder traversal of all leaf nodes.
     *
     * @warning If multiple parent nodes have the same leaf child, the child will be
     * visited multiple times.
     *
     * @param visitor Function to call for each leaf node.
     */
    void visitLeaves(const std::function<void(const K&, const T&)>& visitor)
    {
        auto _visitor = [&](const K& id, const T& node)
        {
            if (!hasChildren(id))
            {
                visitor(id, node);
            }
        };
        _preOrder(m_root, _visitor);
    }

    /**
     * @brief Get the Graph Str object
     *
     * @return std::string Graphviz representation.
     */
    std::string getGraphStr() const
    {
        std::stringstream ss;
        ss << "strict digraph G {\n";

        auto visitor = [&](const std::string& id, auto& visitRef) -> void
        {
            if (hasChildren(id))
            {
                for (auto& child : children(id))
                {
                    ss << fmt::format("\"{}\" -> \"{}\"\n", id, child);
                }
            }
        };

        _preOrder(m_root, visitor);
        ss << "}\n";
        return ss.str();
    }

    friend bool operator==(const Graph& lhs, const Graph& rhs)
    {
        bool root = lhs.m_root == rhs.m_root;
        bool nodes = lhs.m_nodes == rhs.m_nodes;
        bool edges = lhs.m_edges == rhs.m_edges;
        return root && nodes && edges;
    }
};

#endif // _GRAPH_H

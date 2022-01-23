#include <type_traits>

#include "rxcpp/rx.hpp"

namespace graph
{
/**
 * @brief The node class is the building block of a graph. In this
 * implementation a graph is a network of connected nodes.
 *
 * The implementation allow loops.
 *
 * @tparam T
 */
template <class T> class Node
{
    using node_ptr_t = std::shared_ptr<Node<T>>;
    using node_ptr_list_t = std::vector<node_ptr_t>;

private:
    node_ptr_list_t m_childs;

public:
    std::shared_ptr<T> m_value;
    /**
     * @brief A node contains a pointer to a value and a list
     * of of pointers to its child nodes.
     *
     * @param value
     */
    Node(std::shared_ptr<T> value) : m_value(value){};

    /**
     * @brief connects this to node n.
     *
     * @param n
     */
    void connect(node_ptr_t n)
    {
        this->m_value->connect(n->m_value);
        this->m_childs.push_back(n);
    }

    /**
     * @brief returns the name of the underlying asset, to check
     * for its identity. The node uses the asset identity as its own.
     *
     * @return std::string name of the underlaying value
     */
    auto name() const
    {
        return this->m_value->name();
    }

    /**
     * @brief return the list of adjacent nodes, ie. all nodes
     * subscribed to this one.
     *
     * @return std::vector<Node<T>>
     */
    auto adjacents() const
    {
        return this->m_childs;
    }
};

/**
 * @brief visit all leaves of the graph to which this node
 * is the root node, only once.
 *
 * @param n root node
 * @param fn visitor function
 */
template <class T> void visitLeaves(std::shared_ptr<Node<T>> n, std::function<void(std::shared_ptr<Node<T>>)> fn)
{
    using node_ptr_t = std::shared_ptr<Node<T>>;
    std::map<node_ptr_t, bool> v;
    std::function<void(node_ptr_t, std::function<void(node_ptr_t)>)> inner_visit;

    inner_visit = [&](node_ptr_t curr, std::function<void(node_ptr_t)> fn)
    {
        auto adj = curr->adjacents();
        if (adj.size() > 0)
        {
            std::for_each(adj.begin(), adj.end(),
                          [&](auto c)
                          {
                              if (v.find(c) == v.end())
                              {
                                  v.insert(std::pair(c, true));
                                  inner_visit(c, fn);
                              }
                          });
        }
        else
        {
            v.insert(std::pair(curr, true));
            fn(curr);
        }
    };
    inner_visit(n, fn);
}

/**
 * @brief Visit all edges of the graph, only once
 *
 * @param n root node
 * @param fn visitor function
 */
template <class T>
void visit(std::shared_ptr<Node<T>> n,
           std::function<void(std::pair<std::shared_ptr<Node<T>>, std::shared_ptr<Node<T>>>)> fn)
{

    using pNode_t = std::shared_ptr<Node<T>>;
    using Edge_t = std::pair<pNode_t, pNode_t>;
    using Fn_t = std::function<void(Edge_t)>;

    std::map<Edge_t, bool> visited;

    std::function<void(Edge_t, Fn_t)> inner_visit;

    inner_visit = [&](Edge_t curr, Fn_t fn)
    {
        if (visited.find(curr) == visited.end())
        {
            fn(curr);
            visited.insert(std::pair(curr, true));
            auto adj = curr.second->adjacents();
            std::for_each(adj.begin(), adj.end(), [&](auto next) { inner_visit(Edge_t(curr.second, next), fn); });
        }
    };
    inner_visit(Edge_t(n, n), fn);
}

/**
 * @brief returns a string stream with a graphviz representation of
 * the graph starting an the node root
 *
 * @tparam T
 * @param root of the graph to represent
 * @return std::stringstream containing the representation
 */
template <class T> std::stringstream print(std::shared_ptr<Node<T>> root)
{
    std::stringstream diagraph;
    diagraph << "digraph G {" << std::endl;
    graph::visit<T>(root, [&](auto pair)
                    { diagraph << pair.first->name() << " -> " << pair.second->name() << ";" << std::endl; });
    diagraph << "}" << std::endl;
    return diagraph;
}

} // namespace graph

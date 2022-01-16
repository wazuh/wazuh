#include <type_traits>

#include "rxcpp/rx.hpp"

namespace graph
{
    template <typename T, typename F>
    constexpr auto has_member_impl(F &&f) -> decltype(f(std::declval<T>()), true)
    {
        return true;
    }

    template <typename>
    constexpr bool has_member_impl(...) { return false; }

    /**
     * @brief returns true if T has a member called EXPR
     *
     */
    #define HAS_MEMBER(T, EXPR) \
        has_member_impl<T>([](auto &&obj) -> decltype(obj.EXPR) {})

    /**
     * @brief A node connects two connectables between them. if a connectable
     * type T. A connectable type has a method to get its observer and the node
     * will connect to other connectable types by chaining their
     * observers together.
     *
     * @tparam T
     */
    template <class T>
    class Node
    {
        typedef std::shared_ptr<Node<T>> NodePtr;
        typedef std::vector<NodePtr> AdjList;

        static_assert(HAS_MEMBER(T, observable()), "Type T requires a method called observable()");
        static_assert(HAS_MEMBER(T, subscriber()), "Type T requires a method called subscriber()");
        static_assert(HAS_MEMBER(T, m_name), "Type T requires a member called m_name");

    private:
        AdjList m_adj;
        std::shared_ptr<T> m_value;

    public:
        /**
         * @brief Construct a new Node object from a T. It expects a
         * std::shared_ptr<T> because it will take ownership of T, and will
         * change it by making the appropriate subscriptions.
         *
         * @param value
         */
        Node(std::shared_ptr<T> value) : m_value(std::move(value)){};

        /**
         * @brief connects node n as a subscriber to the events this node might
         * generate.
         *
         * @param n
         */
        void connect(const NodePtr n)
        {
            AdjList nc = n->adjacents();
            auto res = std::find_if(std::begin(nc), std::end(nc),
                                    [&](const NodePtr &e)
                                    { return this->m_value->m_name == e->m_value->m_name; });

            if (res != std::end(nc))
            {
                throw std::invalid_argument("Loop detected.");
            }

            this->m_value->observable().subscribe(n->subscriber());

            this->m_adj.push_back(n);
        }
        /**
         * @brief returns the underlying observable of this node so
         * other node can subscribe to it.
         *
         * @return rxcpp::observable<E>
         */
        auto observable() const { return this->m_value->observable(); }
        /**
         * @brief returns the underlying subscriber of this node so
         * it can be subscribed to other node.
         *
         * @return rxcpp::subscriber<T>
         */
        auto subscriber() const { return this->m_value->subscriber(); }
        /**
         * @brief returns the name of the underlying asset, to check
         * for identity. The graph node uses the asset identity as its own.
         *
         * @return std::string
         */
        auto name() const { return this->m_value->m_name; }
        /**
         * @brief return the list of adjacent nodes, ie. all nodes
         * subscribed to this one.
         *
         * @return std::vector<Node<T>>
         */
        auto adjacents() const { return this->m_adj; }

        /**
         * @brief visit all leaves of the graph to which this node
         * is the root node.
         *
         * @param fn
         */
        void visitLeaves(std::function<void(Node<T> *)> fn)
        {
            if (this->m_adj.size() > 0)
            {
                std::for_each(this->m_adj.begin(), this->m_adj.end(), [fn](auto c)
                              { c->visitLeaves(fn); });
            }
            else
            {
                fn(this);
            }
        }
    };
} // Graph namespace

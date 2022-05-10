#ifndef _CONNECTABLE_H
#define _CONNECTABLE_H

#include <functional>
#include <memory>
#include <random>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

namespace builder
{
namespace internals
{

class Connectable : public std::enable_shared_from_this<Connectable>
{
private:
    // static method to generate unique id for each instance
    static std::string generateId()
    {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 99999);
        std::stringstream ss;
        ss << dis(gen);
        return ss.str();
    }

protected:
    Connectable() = default;
    explicit Connectable(std::string&& name)
        : m_name(std::move(name))
    {
        m_name += "[" + generateId() + "]";
    }

public:
    std::string m_name;
    virtual ~Connectable() = default;

    void changeName(const std::string& name)
    {
        auto pos = m_name.find("[");
        if (pos != std::string::npos)
        {
            m_name = name + m_name.substr(pos);
        }
    }

    template<typename Derived>
    std::shared_ptr<Derived> getPtr()
    {
        static_assert(std::is_base_of_v<Connectable, Derived>,
                      "Derived must be a subclass of Connectable");
        auto ptr = std::dynamic_pointer_cast<Derived>(shared_from_this());
        if (!ptr)
        {
            throw std::runtime_error(
                fmt::format("Error trying to downcast [{}] to [{}], this "
                            "Connectable type is [{}]",
                            typeid(std::shared_ptr<Connectable>).name(),
                            typeid(std::shared_ptr<Derived>).name(),
                            typeid(decltype(shared_from_this())).name()));
        }
        return ptr;
    }

    template<typename Derived>
    std::shared_ptr<const Derived> getPtr() const
    {
        static_assert(std::is_base_of_v<Connectable, Derived>,
                      "Derived must be a subclass of Connectable");
        auto ptr = std::dynamic_pointer_cast<const Derived>(shared_from_this());
        if (!ptr)
        {
            throw std::runtime_error(
                fmt::format("Error trying to downcast [{}] to [{}], this "
                            "Connectable type is [{}]",
                            typeid(std::shared_ptr<const Connectable>).name(),
                            typeid(std::shared_ptr<const Derived>).name(),
                            typeid(decltype(shared_from_this())).name()));
        }
        return ptr;
    }

    virtual bool isGroup() const
    {
        return false;
    }

    virtual bool isOperation() const
    {
        return false;
    }

    virtual bool isAsset() const
    {
        return false;
    }
};

template<typename Operation>
class ConnectableOperation : public Connectable
{
private:
    Operation m_operation;

public:
    [[nodiscard]] static std::shared_ptr<ConnectableOperation> create()
    {
        return std::shared_ptr<ConnectableOperation>(
            new ConnectableOperation());
    }

    [[nodiscard]] static std::shared_ptr<ConnectableOperation>
    create(std::string name, Operation&& operation)
    {
        return std::shared_ptr<ConnectableOperation>(
            new ConnectableOperation(std::move(name), std::move(operation)));
    }

    bool isOperation() const override
    {
        return true;
    }

    Operation getOperation() const
    {
        return m_operation;
    }

private:
    ConnectableOperation() = default;
    explicit ConnectableOperation(std::string&& name, Operation&& operation)
        : Connectable {std::move(name)}
        , m_operation {std::move(operation)}
    {
    }
};

class ConnectableGroup : public Connectable
{
public:
    virtual ~ConnectableGroup() = default;
    enum GroupType
    {
        FIRST_SUCCESS,
        FIRST_ERROR,
        CHAIN,
        FALLIBLE_CHAIN
    };

    GroupType m_type;
    std::vector<std::shared_ptr<Connectable>> m_connectables;

    bool isGroup() const override
    {
        return true;
    }

    [[nodiscard]] static std::shared_ptr<ConnectableGroup> create()
    {
        return std::shared_ptr<ConnectableGroup>(new ConnectableGroup());
    }

    [[nodiscard]] static std::shared_ptr<ConnectableGroup>
    create(std::string&& name,
           GroupType type,
           std::vector<std::shared_ptr<Connectable>> connectables = {})
    {
        return std::shared_ptr<ConnectableGroup>(new ConnectableGroup(
            std::move(name), type, std::move(connectables)));
    }

protected:
    ConnectableGroup() = default;
    ConnectableGroup(std::string&& name,
                     GroupType type,
                     std::vector<std::shared_ptr<Connectable>>&& connectables)
        : Connectable {std::move(name)}
        , m_type {type}
        , m_connectables {std::move(connectables)}
    {
    }

private:
};

class ConnectableAsset : public ConnectableGroup
{
public:
    std::vector<std::string> m_parents;
    std::unordered_map<std::string, std::any> m_metadata;

    bool isAsset() const override
    {
        return true;
    }

    [[nodiscard]] static std::shared_ptr<ConnectableAsset> create()
    {
        return std::shared_ptr<ConnectableAsset>(new ConnectableAsset());
    }

    [[nodiscard]] static std::shared_ptr<ConnectableAsset>
    create(ConnectableGroup::GroupType type,
           std::string name,
           std::vector<std::shared_ptr<Connectable>> connectables = {},
           std::vector<std::string> parents = {},
           std::unordered_map<std::string, std::any> metadata = {})
    {
        return std::shared_ptr<ConnectableAsset>(
            new ConnectableAsset(type,
                                 std::move(connectables),
                                 std::move(name),
                                 std::move(parents),
                                 std::move(metadata)));
    }

private:
    ConnectableAsset() = default;
    ConnectableAsset(ConnectableGroup::GroupType type,
                     std::vector<std::shared_ptr<Connectable>>&& connectables,
                     std::string&& name,
                     std::vector<std::string>&& parents,
                     std::unordered_map<std::string, std::any>&& metadata)
        : ConnectableGroup(std::move(name), type, std::move(connectables))
        , m_parents {std::move(parents)}
        , m_metadata {std::move(metadata)}
    {
    }
};

class ConnectableNode: public ConnectableGroup
{
//TODO: implement
};

// Utils
static std::string groupTypeToStr(ConnectableGroup::GroupType type)
{
    switch (type)
    {
        case ConnectableGroup::GroupType::CHAIN: return "CHAIN";
        case ConnectableGroup::GroupType::FALLIBLE_CHAIN:
            return "FALLIBLE_CHAIN";
        case ConnectableGroup::GroupType::FIRST_SUCCESS: return "FIRST_SUCCESS";
        case ConnectableGroup::GroupType::FIRST_ERROR: return "FIRST_ERROR";
        default: return "ERRORRRR";
    }
}

static void Optimize(std::shared_ptr<Connectable> root)
{
    auto optimize = [](std::shared_ptr<ConnectableGroup>& parent,
                       std::shared_ptr<Connectable>& child,
                       size_t& pos)
    {
        // Do not optimize if child has multiple parents
        if (child->isAsset())
        {
            auto asset = child->getPtr<ConnectableAsset>();
            if (asset->m_parents.size() > 1)
            {
                return;
            }
        }
        if (parent->m_connectables.size() == 1)
        {
            if (child->isGroup())
            {
                auto childGroup = child->getPtr<ConnectableGroup>();
                if (childGroup->m_connectables.size() == 1 ||
                    childGroup->m_type >= parent->m_type)
                {
                    auto type = childGroup->m_type > parent->m_type
                                    ? childGroup->m_type
                                    : parent->m_type;
                    parent->m_type = type;
                    parent->m_connectables = childGroup->m_connectables;
                    child = parent;
                }
            }
        }
        else
        {
            if (child->isGroup())
            {
                auto childGroup = child->getPtr<ConnectableGroup>();
                if (childGroup->m_connectables.empty())
                {
                    parent->m_connectables.erase(
                        parent->m_connectables.begin() + pos);
                }
                else if (childGroup->m_type == parent->m_type)
                {
                    parent->m_connectables.erase(
                        parent->m_connectables.begin() + pos);
                    parent->m_connectables.insert(
                        parent->m_connectables.begin() + pos,
                        childGroup->m_connectables.begin(),
                        childGroup->m_connectables.end());
                    // pos = pos + childGroup->m_connectables.size();
                    pos = parent->m_connectables.size();
                    child = parent;
                }
            }
        }
    };

    auto advance = [&](std::shared_ptr<Connectable>& current,
                       auto& advanceRef) -> void
    {
        if (current->isGroup())
        {
            std::shared_ptr<ConnectableGroup> parentGroup =
                current->getPtr<ConnectableGroup>();
            for (size_t i = 0; i < parentGroup->m_connectables.size(); ++i)
            {
                std::shared_ptr<Connectable> child =
                    parentGroup->m_connectables[i];

                optimize(parentGroup, child, i);
                advanceRef(child, advanceRef);
            }
        }
    };

    advance(root, advance);
}

static std::string
getGraphivStr(const std::shared_ptr<const ConnectableGroup>& root)
{
    std::stringstream ss;
    ss << "strict digraph G {\n";
    auto replaceQuotes = [](const std::string& str)
    {
        std::string result;
        std::replace_copy_if(
            str.begin(),
            str.end(),
            std::back_inserter(result),
            [](char c) { return c == '"'; },
            '\'');
        return result;
    };
    auto visit = [&](const std::shared_ptr<const Connectable>& connectable,
                     auto& visitRef) -> void
    {
        if (connectable->isGroup())
        {
            auto c = connectable->getPtr<const ConnectableGroup>();
            auto siblingOrder = 0;
            for (auto child : c->m_connectables)
            {

                if (child->isGroup())
                {
                    auto c1 = child->getPtr<const ConnectableGroup>();
                    ss << fmt::format("\"{}\" -> \"{}\" [label=\"{}_{}\"];\n",
                                      replaceQuotes(c->m_name),
                                      replaceQuotes(c1->m_name),
                                      groupTypeToStr(c->m_type),
                                      siblingOrder);
                    visitRef(child, visitRef);
                }
                else if (child->isOperation())
                {
                    ss << fmt::format("\"{}\" -> \"{}\" [label=\"{}_{}\"];\n",
                                      replaceQuotes(c->m_name),
                                      replaceQuotes(child->m_name),
                                      groupTypeToStr(c->m_type),
                                      siblingOrder);
                }
                ++siblingOrder;
            }
        }
    };
    visit(root, visit);
    ss << "}\n";
    return ss.str();
}
} // namespace internals
} // namespace builder

#endif // _CONNECTABLE_H

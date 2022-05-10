#include <algorithm>
#include <any>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "_builder/connectable.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"
#include "_builder/operation.hpp"
#include "_builder/registry.hpp"

namespace
{
using namespace builder::internals;

RegisterBuilder firstSuccessGraph {
    "firstSuccessGraph",
    [](const std::any& definition) -> std::shared_ptr<Connectable>
    {
        auto [rootName, assetsNodes, childrenRel] = std::any_cast<std::tuple<
            std::string,
            std::unordered_map<std::string, std::shared_ptr<ConnectableGroup>>,
            std::unordered_map<std::string, std::unordered_set<std::string>>>>(
            definition);

        // Make graph
        auto visitor = [&](std::string current,
                           auto& visitorRef) -> std::shared_ptr<Connectable>
        {
            auto currentNode = assetsNodes[current];
            if (childrenRel.find(current) != childrenRel.end())
            {
                auto childrenNode = ConnectableGroup::create(
                    "children", ConnectableGroup::FIRST_SUCCESS);

                for (auto& child : childrenRel[current])
                {
                    childrenNode->m_connectables.push_back(
                        visitorRef(child, visitorRef));
                }

                currentNode->m_connectables.push_back(childrenNode);
            }
            return currentNode;
        };

        auto rootNode =
            ConnectableAsset::create(ConnectableGroup::FIRST_SUCCESS, rootName);
        for (auto& childName : childrenRel[rootName])
        {
            rootNode->m_connectables.push_back(visitor(childName, visitor));
        }

        return rootNode;
    }};

RegisterBuilder FallibleGraph {
    "fallibleGraph",
    [](const std::any& definition) -> std::shared_ptr<Connectable>
    {
        auto [rootName, assetsNodes, childrenRel] = std::any_cast<std::tuple<
            std::string,
            std::unordered_map<std::string, std::shared_ptr<ConnectableGroup>>,
            std::unordered_map<std::string, std::unordered_set<std::string>>>>(
            definition);

        // Make graph
        auto visitor = [&](std::string current,
                           auto& visitorRef) -> std::shared_ptr<Connectable>
        {
            auto currentNode = assetsNodes[current];
            if (childrenRel.find(current) != childrenRel.end())
            {
                auto childrenNode = ConnectableGroup::create(
                    "children", ConnectableGroup::FALLIBLE_CHAIN);

                for (auto& child : childrenRel[current])
                {
                    childrenNode->m_connectables.push_back(
                        visitorRef(child, visitorRef));
                }
                childrenNode->m_connectables.push_back(currentNode);
            }
            return currentNode;
        };

        auto rootNode = ConnectableAsset::create(
            ConnectableGroup::FALLIBLE_CHAIN, rootName);
        for (auto& childName : childrenRel[rootName])
        {
            rootNode->m_connectables.push_back(visitor(childName, visitor));
        }

        return rootNode;
    }};

} // namespace

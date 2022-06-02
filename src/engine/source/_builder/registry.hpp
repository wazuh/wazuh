#ifndef _REGISTRY_H
#define _REGISTRY_H

#include <any>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <fmt/format.h>

#include "_builder/event.hpp"
#include "_builder/expression.hpp"

// namespace builder::internals
// {

using Builder = std::function<Expression(std::any)>;
class Registry
{
private:
    std::unordered_map<std::string, Builder> m_builders;

    Registry() = default;
    Registry(const Registry&) = delete;
    Registry& operator=(const Registry&) = delete;
    Registry(Registry&&) = delete;
    Registry& operator=(Registry&&) = delete;

public:
    static auto& instance()
    {
        static Registry instance;
        return instance;
    }

    static Builder& getBuilder(const std::string& name)
    {
        if (Registry::instance().m_builders.find(name) ==
            Registry::instance().m_builders.end())
        {
            throw std::runtime_error(
                fmt::format("Builder [{}] not registered", name));
        }
        return Registry::instance().m_builders.at(name);
    }

    // Register Builder
    template<typename... Names>
    static void registerBuilder(Builder builder, Names... names)
    {
        for (auto name : {names...})
        {
            if (Registry::instance().m_builders.find(name) ==
                Registry::instance().m_builders.end())
            {
                Registry::instance().m_builders.insert(
                    std::make_pair(name, builder));
            }
            else
            {
                throw std::logic_error(fmt::format(
                    "Error, trying to register a builder with name [{}], but a "
                    "builder with that name already exists",
                    name));
            }
        }
    }

    static void clear()
    {
        Registry::instance().m_builders.clear();
    }
};

// } // namespace builder::internals

#endif // _REGISTRY_H

#ifndef _REGISTRY_H
#define _REGISTRY_H

#include <any>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <fmt/format.h>

#include "_builder/connectable.hpp"

namespace builder
{
namespace internals
{

using Builder = std::function<std::shared_ptr<Connectable>(std::any)>;
class Registry
{
private:
    friend struct RegisterBuilder;
    std::unordered_map<std::string, Builder> m_builders;
    Registry() = default;

    // Register Builder
    void registerBuilder(std::string&& name, Builder&& builder)
    {
        if (m_builders.find(name) == m_builders.end())
        {
            m_builders.insert(
                std::make_pair(std::move(name), std::move(builder)));
        }
        else
        {
            throw std::logic_error(fmt::format(
                "Error, trying to register a builder with name [{}], but a "
                "builder with that name already exists",
                name));
        }
    }

public:
    Registry(const Registry&) = delete;
    Registry& operator=(const Registry&) = delete;
    Registry(Registry&&) = delete;
    Registry& operator=(Registry&&) = delete;

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
};

struct RegisterBuilder
{
    RegisterBuilder() = delete;
    RegisterBuilder(const RegisterBuilder&) = delete;
    RegisterBuilder& operator=(const RegisterBuilder&) = delete;
    RegisterBuilder(RegisterBuilder&&) = delete;
    RegisterBuilder& operator=(RegisterBuilder&&) = delete;

    RegisterBuilder(std::string&& name, Builder&& buildFunction)
    {
        Registry::instance().registerBuilder(
            std::move(name), Builder {std::move(buildFunction)});
    }
};

} // namespace internals
} // namespace builder

#endif // _REGISTRY_H

#ifndef _REGISTRY_H
#define _REGISTRY_H

#include <any>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <fmt/format.h>

#include "expression.hpp"

namespace builder::internals
{

using Builder = std::function<base::Expression(std::any)>;

/**
 * @brief Registry of builders.
 *
 * This class is used to register builders and to get builders by name.
 */
class Registry
{
private:
    std::unordered_map<std::string, Builder> m_builders;

public:
    Registry() = default;
    Registry(const Registry&) = delete;
    Registry& operator=(const Registry&) = delete;
    Registry(Registry&&) = delete;
    Registry& operator=(Registry&&) = delete;

    /**
     * @brief Get the Builder object
     *
     * @param name Name of the builder.
     * @return Builder Builder object reference.
     */
    Builder getBuilder(const std::string& name);

    /**
     * @brief Register a builder.
     *
     * @param builder Builder object.
     * @param names Names of the builder.
     */
    template<typename... Names>
    void registerBuilder(Builder builder, Names... names)
    {
        for (auto name : {names...})
        {
            if (m_builders.find(name) == m_builders.end())
            {
                m_builders.insert(std::make_pair(name, builder));
            }
            else
            {

                throw std::logic_error(
                    fmt::format("Engine registry: A builder is already registered with "
                                "name \"{}\", registration failed.",
                                name));
            }
        }
    }

    /**
     * @brief Clear the registry.
     *
     */
    void clear();
};

} // namespace builder::internals

#endif // _REGISTRY_H

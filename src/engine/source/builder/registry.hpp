#ifndef _REGISTRY_H
#define _REGISTRY_H

#include <any>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include "expression.hpp"

namespace builder::internals
{

using Builder = std::function<base::Expression(std::any)>;
using HelperBuilder =
    std::function<base::Expression(const std::string&, const std::string&, const std::vector<std::string>&)>;

/**
 * @brief Registry of builders.
 *
 * This class is used to register builders and to get builders by name.
 */

template<typename T = Builder>
class Registry
{
private:
    std::unordered_map<std::string, T> m_builders;

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
    T getBuilder(const std::string& name)
    {
        if (m_builders.find(name) == m_builders.end())
        {
            throw std::runtime_error(fmt::format("Builder name \"{}\" could not be found in the registry", name));
        }
        return m_builders.at(name);
    }

    /**
     * @brief Register a builder.
     *
     * @param builder Builder object.
     * @param names Names of the builder.
     */
    template<typename... Names>
    void registerBuilder(T builder, Names... names)
    {
        for (auto name : {names...})
        {
            if (m_builders.find(name) == m_builders.end())
            {
                m_builders.insert(std::make_pair(name, builder));
            }
            else
            {

                throw std::logic_error(fmt::format("Engine registry: A builder is already registered with "
                                                   "name \"{}\", registration failed.",
                                                   name));
            }
        }
    }

    /**
     * @brief Clear the registry.
     *
     */
    void clear() { m_builders.clear(); }
};

} // namespace builder::internals

#endif // _REGISTRY_H

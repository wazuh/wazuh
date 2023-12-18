#ifndef _BUILDER2_REGISTRY_HPP
#define _BUILDER2_REGISTRY_HPP

#include <unordered_map>

#include <fmt/format.h>

#include "iregistry.hpp"

namespace builder
{

template<typename Builder>
class Registry : public IRegistry<Builder>
{
private:
    std::unordered_map<std::string, Builder> m_registry; ///< Registry of builders

public:
    Registry() = default;

    /**
     * @copydoc IRegistry<Builder>::add
     */
    inline base::OptError add(const std::string& name, const Builder& entry) override
    {
        if (m_registry.find(name) != m_registry.end())
        {
            return base::Error {fmt::format("Builder '{}' already registered", name)};
        }

        m_registry.emplace(name, entry);
        return base::OptError();
    }

    /**
     * @copydoc IRegistry<Builder>::get
     */
    inline base::RespOrError<Builder> get(const std::string& name) const override
    {
        auto it = m_registry.find(name);
        if (it == m_registry.end())
        {
            return base::Error {fmt::format("Builder '{}' not registered", name)};
        }

        return it->second;
    }
};

} // namespace builder

#endif // _BUILDER2_REGISTRY_HPP

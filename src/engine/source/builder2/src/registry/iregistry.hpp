#ifndef _BUILDER_IREGISRTY_HPP
#define _BUILDER_IREGISRTY_HPP

#include <string>

#include <error.hpp>

namespace builder::registry
{

/**
 * @brief Registry interface, maintains a registry of builders.
 *
 * @tparam Builder Type of the builders.
 */
template<typename Builder>
class IRegistry
{
public:
    virtual ~IRegistry() = default;

    /**
     * @brief Add a builder to the registry.
     *
     * @param name Name of the builder.
     * @param entry Builder to add.
     * @return base::OptError Error if the builder could not be added.
     */
    virtual base::OptError add(const std::string& name, const Builder& entry) = 0;

    /**
     * @brief Get a builder from the registry.
     *
     * @param name Name of the builder.
     * @return base::RespOrError<Builder> Builder if found, error otherwise.
     */
    virtual base::RespOrError<Builder> get(const std::string& name) const = 0;
};

} // namespace builder::registry

#endif // _BUILDER_IREGISRTY_HPP

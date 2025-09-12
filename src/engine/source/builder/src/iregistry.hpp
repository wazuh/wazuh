#ifndef _BUILDER_IREGISRTY_HPP
#define _BUILDER_IREGISRTY_HPP

#include <memory>
#include <string>
#include <tuple>
#include <type_traits>

#include <base/error.hpp>

namespace builder
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

namespace detail
{
// Trait to check if a type is in a variadic list
template<typename T, typename... List>
struct is_in_list;

template<typename T, typename First, typename... Rest>
struct is_in_list<T, First, Rest...> : is_in_list<T, Rest...>
{
};

template<typename T, typename... Rest>
struct is_in_list<T, T, Rest...> : std::true_type
{
};

template<typename T>
struct is_in_list<T> : std::false_type
{
};
} // namespace detail

template<typename... Builders>
class MetaRegistry : public std::enable_shared_from_this<MetaRegistry<Builders...>>
{
private:
    std::tuple<std::shared_ptr<IRegistry<Builders>>...> m_registryTuple;

    MetaRegistry() = default;

    template<typename Builder, template<typename> typename Registry>
    void instantiate()
    {
        std::get<std::shared_ptr<IRegistry<Builder>>>(m_registryTuple) = std::make_shared<Registry<Builder>>();
    }

protected: // To expose registry tuple in the mock class
    auto& getRegistryTuple() { return m_registryTuple; }

public:
    // Static create method with a template template parameter
    template<template<typename> typename Registry>
    [[nodiscard]] static std::shared_ptr<MetaRegistry> create()
    {
        auto ptr = std::shared_ptr<MetaRegistry>(new MetaRegistry());

        // Instantiate all the registries
        (ptr->template instantiate<Builders, Registry>(), ...);

        return ptr;
    }

    template<typename Builder>
    void add(const std::string& name, const Builder& entry)
    {
        static_assert(detail::is_in_list<Builder, Builders...>::value,
                      "Builder type is not registered in MetaRegistry.");

        using RequiredRegistry = IRegistry<Builder>;
        auto& registry = std::get<std::shared_ptr<RequiredRegistry>>(m_registryTuple);

        registry->add(name, entry);
    }

    template<typename Builder>
    auto get(const std::string& name) const
    {
        static_assert(detail::is_in_list<Builder, Builders...>::value,
                      "Builder type is not registered in MetaRegistry.");

        using RequiredRegistry = IRegistry<Builder>;
        auto& registry = std::get<std::shared_ptr<RequiredRegistry>>(m_registryTuple);

        return registry->get(name);
    }
};

} // namespace builder

#endif // _BUILDER_IREGISRTY_HPP

#ifndef _BASE_SINGLETONLOCATOR_HPP
#define _BASE_SINGLETONLOCATOR_HPP

#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <type_traits>
#include <typeindex>
#include <typeinfo>

/**
 * @brief Base singleton manager class. This allows for heterogeneous singleton management.
 *
 */
class BaseSingletonManager
{
public:
    virtual ~BaseSingletonManager() = default;
};

/**
 * @brief Singleton strategy interface. This interface defines the methods required to manage a singleton instance.
 *
 * @tparam Instance Type of the singleton instance being managed.
 */
template<typename Instance>
class ISingletonManager : public BaseSingletonManager
{
public:
    ~ISingletonManager() override = default;

    /**
     * @brief Get the managed singleton instance.
     *
     * @return Instance& Reference to the singleton instance.
     */
    virtual Instance& instance() = 0;
};

/**
 * @brief Singleton locator class. This class provides a way to access singleton instances.
 *
 */
class SingletonLocator
{
private:
    static std::shared_mutex& registryMutex()
    {
        static std::shared_mutex m_registryMutex;
        return m_registryMutex;
    }

    static auto& strategyRegistry()
    {
        static std::map<std::type_index, std::unique_ptr<BaseSingletonManager>> m_strategyRegistry;
        return m_strategyRegistry;
    }

public:
    /**
     * @brief Register a singleton manager strategy for a given instance type.
     *
     * @tparam Instance The singleton instance type.
     * @tparam Strategy The manager strategy (must inherit from ISingletonManager<Instance>).
     * @throws std::logic_error If a manager is already registered for this type.
     */
    template<typename Instance, class Strategy>
    static void registerManager()
    {
        static_assert(std::is_base_of_v<ISingletonManager<Instance>, Strategy>,
                      "Strategy must inherit from ISingletonManager for the specified Instance type.");
        static_assert(std::is_default_constructible_v<Strategy>, "Strategy must be default constructible.");

        // Register the manager for the specified type
        std::unique_lock lock(registryMutex());
        if (strategyRegistry().find(std::type_index(typeid(Instance))) != strategyRegistry().end())
        {
            throw std::logic_error("Manager already registered for this type.");
        }

        strategyRegistry()[std::type_index(typeid(Instance))] = std::make_unique<Strategy>();
    }

    /**
     * @brief Unregister the singleton manager for a given instance type.
     *
     * @tparam Instance The singleton instance type.
     * @throws std::logic_error If no manager is registered for this type.
     */
    template<typename Instance>
    static void unregisterManager()
    {
        std::unique_lock lock(registryMutex());
        if (strategyRegistry().find(std::type_index(typeid(Instance))) == strategyRegistry().end())
        {
            throw std::logic_error("No manager registered for this type.");
        }

        strategyRegistry().erase(std::type_index(typeid(Instance)));
    }

    /**
     * @brief Get the singleton instance for a given type.
     *
     * @tparam Instance The singleton instance type.
     * @return Instance& Reference to the singleton instance.
     * @throws std::logic_error If no manager is registered for this type.
     */
    template<typename Instance>
    static Instance& instance()
    {
        std::shared_lock lock(registryMutex());
        auto it = strategyRegistry().find(std::type_index(typeid(Instance)));
        if (it == strategyRegistry().end())
        {
            throw std::logic_error("No manager registered for this type.");
        }

        return static_cast<ISingletonManager<Instance>*>(it->second.get())->instance();
    }

    /**
     * @brief Get the singleton manager for a given instance type.
     *
     * @tparam Instance The singleton instance type.
     * @return ISingletonManager<Instance>& Reference to the manager.
     * @throws std::logic_error If no manager is registered for this type.
     */
    template<typename Instance>
    static ISingletonManager<Instance>& manager()
    {
        std::shared_lock lock(registryMutex());
        auto it = strategyRegistry().find(std::type_index(typeid(Instance)));
        if (it == strategyRegistry().end())
        {
            throw std::logic_error("No manager registered for this type.");
        }

        return static_cast<ISingletonManager<Instance>&>(*it->second);
    }

    /**
     * @brief Remove all registered singleton managers.
     */
    static void clear()
    {
        std::unique_lock lock(registryMutex());
        strategyRegistry().clear();
    }
};

#endif // _BASE_SINGLETONLOCATOR_HPP

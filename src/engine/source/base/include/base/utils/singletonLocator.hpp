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

    static void clear()
    {
        std::unique_lock lock(registryMutex());
        strategyRegistry().clear();
    }
};

#endif // _BASE_SINGLETONLOCATOR_HPP

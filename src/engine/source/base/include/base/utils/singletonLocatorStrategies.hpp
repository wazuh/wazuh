#ifndef _BASE_SINGLETONLOCATORSTRATEGIES_HPP
#define _BASE_SINGLETONLOCATORSTRATEGIES_HPP

#include <base/utils/singletonLocator.hpp>

namespace base
{
/**
 * @brief Singleton manager strategy that owns the instance via unique_ptr.
 *
 * Creates the concrete Instance on construction and exposes it through
 * the IInstance interface.
 *
 * @tparam IInstance The interface type exposed.
 * @tparam Instance The concrete implementation type (must derive from IInstance).
 */
template<typename IInstance, typename Instance>
class PtrSingleton : public ISingletonManager<IInstance>
{
private:
    std::unique_ptr<Instance> m_instance; ///< Owned singleton instance.

public:
    /**
     * @brief Construct and allocate the singleton instance.
     */
    PtrSingleton()
        : m_instance(std::make_unique<Instance>())
    {
        static_assert(std::is_base_of<IInstance, Instance>::value, "Instance must be derived from IInstance");
    }
    ~PtrSingleton() override = default;

    /**
     * @copydoc ISingletonManager::instance
     */
    IInstance& instance() override { return static_cast<IInstance&>(*m_instance); }
};

} // namespace base

#endif // _BASE_SINGLETONLOCATORSTRATEGIES_HPP

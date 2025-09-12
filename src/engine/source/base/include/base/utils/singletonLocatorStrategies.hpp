#ifndef _BASE_SINGLETONLOCATORSTRATEGIES_HPP
#define _BASE_SINGLETONLOCATORSTRATEGIES_HPP

#include <base/utils/singletonLocator.hpp>

namespace base
{
template<typename IInstance, typename Instance>
class PtrSingleton : public ISingletonManager<IInstance>
{
private:
    std::unique_ptr<Instance> m_instance;

public:
    PtrSingleton()
        : m_instance(std::make_unique<Instance>())
    {
        static_assert(std::is_base_of<IInstance, Instance>::value, "Instance must be derived from IInstance");
    }
    ~PtrSingleton() override = default;

    IInstance& instance() override { return static_cast<IInstance&>(*m_instance); }
};

} // namespace base

#endif // _BASE_SINGLETONLOCATORSTRATEGIES_HPP

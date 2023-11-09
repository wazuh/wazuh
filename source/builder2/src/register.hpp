#ifndef _BUILDER2_REGISTER_HPP
#define _BUILDER2_REGISTER_HPP

#include <memory>

#include "registry/iregistry.hpp"

namespace builder::detail
{

/**
 * @brief Register all the operation builders.
 *
 * @tparam T Type of the builders.
 * @param registry Registry of builders.
 */
template<typename T>
void registerOpBuilders(const std::shared_ptr<registry::IRegistry<T>>& registry)
{
}
// inline void registerStageBuilders(const std::shared_ptr<StageRegistry>& registry) {}
} // namespace builder::detail

#endif // _BUILDER2_REGISTER_HPP

#ifndef _ASSET_BUILDER_H
#define _ASSET_BUILDER_H

#include "registry.hpp"
#include <functional>
#include <string>

namespace builder::internals {

template <class> class AssetBuilder;
template <class Operation, class... BuildArgs>
class AssetBuilder<Operation(BuildArgs...)> {
private:
  using this_t = AssetBuilder<Operation(BuildArgs...)>;
  std::string m_name;
  std::function<Operation(BuildArgs...)> m_build;

public:
  AssetBuilder(){};
  AssetBuilder(const std::string &name,
               std::function<Operation(BuildArgs...)> buildFunction)
      : m_name{name}, m_build{buildFunction} {
    Registry::instance().registerBuilder<this_t>(this->m_name, *this);
  }

  AssetBuilder(const AssetBuilder<Operation(BuildArgs...)> &other)
      : m_name{other.m_name}, m_build{other.m_build} {}

  AssetBuilder<Operation(BuildArgs...)> &
  operator=(const AssetBuilder<Operation(BuildArgs...)> &other) {
    this->m_name = other.m_name;
    this->m_build = other.m_build;
    return *this;
  }

  Operation operator()(BuildArgs... args) const {
    return this->m_build(args...);
  }
};
} // namespace builder::internals

#endif // _ASSET_BUILDER_H

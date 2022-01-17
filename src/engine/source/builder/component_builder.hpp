#ifndef _COMPONENT_BUILDER_H
#define _COMPONENT_BUILDER_H

#include <functional>
#include <string>

namespace builder::internals {

template <class> class ComponentBuilder;
template <class Operation, class... BuildArgs>
class ComponentBuilder<Operation(BuildArgs...)> {
private:
  std::string m_name;
  std::function<Operation(BuildArgs...)> m_build;

public:
  ComponentBuilder(){};
  ComponentBuilder(const std::string &name,
          std::function<Operation(BuildArgs...)> buildFunction)
      : m_name{name}, m_build{buildFunction} {}

  ComponentBuilder(const ComponentBuilder<Operation(BuildArgs...)> &other)
      : m_name{other.m_name}, m_build{other.m_build} {}

  ComponentBuilder<Operation(BuildArgs...)> &
  operator=(const ComponentBuilder<Operation(BuildArgs...)> &other) {
    this->m_name = other.m_name;
    this->m_build = other.m_build;
    return *this;
  }

  Operation operator()(BuildArgs... args) const {
    return this->m_build(args...);
  }
};
} // namespace builder::internals

#endif // _COMPONENT_BUILDER_H

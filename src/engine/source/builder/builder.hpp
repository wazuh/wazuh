#ifndef _BUILDER_H
#define _BUILDER_H

#include <functional>
#include <string>

namespace builder::internals {

template <class> class Builder;
template <class Operation, class... BuildArgs>
class Builder<Operation(BuildArgs...)> {
private:
  std::string m_name;
  std::function<Operation(BuildArgs...)> m_build;

public:
  Builder(){};
  Builder(const std::string &name,
          std::function<Operation(BuildArgs...)> buildFunction)
      : m_name{name}, m_build{buildFunction} {}

  Builder(const Builder<Operation(BuildArgs...)> &other)
      : m_name{other.m_name}, m_build{other.m_build} {}

  Builder<Operation(BuildArgs...)> &
  operator=(const Builder<Operation(BuildArgs...)> &other) {
    this->m_name = other.m_name;
    this->m_build = other.m_build;
    return *this;
  }

  Operation operator()(BuildArgs... args) const {
    return this->m_build(args...);
  }
};
} // namespace builder::internals

#endif // _BUILDER_H

#ifndef _REGISTRY_H
#define _REGISTRY_H

#include <map>
#include <string>
#include <typeinfo>
#include <typeindex>

namespace builder::internals {
/**
 * @brief Manage specific builders.
 *
 * It implements a key value registry that stores all registred managers and act
 * as the interface to retreive them.
 */
class Registry {
private:
  /**
   * @brief Declared private to implement Meyer's singleton.
   */
  Registry() {}

  /**
   * @brief Declared private to implement Meyer's singleton.
   */
  ~Registry() {}

  /**
   * @brief registry that holds all Builders.
   */
  template <class T>
  static std::map<std::type_index, std::map<std::string, T>> m_registry;

public:
  /**
   * @brief Get instance.
   * Implementes <a
   * href="https://en.wikipedia.org/wiki/Talk%3ASingleton_pattern#Meyers_singleton">Meyer's
   * singleton</a>.
   *
   * @return Registry instance reference.
   */
  static Registry &instance() {
    static Registry s_instance;
    return s_instance;
  }

  /**
   * @brief Deleted to implement Meyer's singleton.
   */
  Registry(const Registry &) = delete;

  /**
   * @brief Deleted to implement Meyer's singleton.
   */
  Registry &operator=(const Registry &) = delete;

  /**
   * @brief Register a Builder.
   *
   * @param builderId Unique Builder id string.
   * @param builder Builder object.
   */
  template <class T>
  void registerBuilder(const std::string &builderId, const T &builder) {
    if (Registry::m_registry<T>[std::type_index(typeid(T))].count(builderId) > 0) {
      throw std::invalid_argument("Builder " + builderId +
                                  " is already stored on the registry");
    } else {
      Registry::m_registry<T>[std::type_index(typeid(T))][builderId] = builder;
    }
  }

  /**
   * @brief Get the builder object
   *
   * @param builderId Builder name to be retreived.
   * @return Builder object.
   */
  template <class T> const T &builder(const std::string &builderId) const {
    return Registry::m_registry<T>[std::type_index(typeid(T))].at(builderId);
  }
};

template<class T>
std::map<std::type_index, std::map<std::string, T>> Registry::m_registry;
} // namespace builder::internals

#endif // _REGISTRY_H

#ifndef _UTILS_H
#define _UTILS_H

#include <string>
#include <vector>

/**
 * @brief defines helper classes and functions for builders.
 *
 */
namespace builder::internals::utils {

/**
 * @brief Represents a json path string.
 *
 * This class splits json path strings to its individual components.
 *
 */
class JsonPath {
private:
  std::vector<std::string> m_jsonPath;

public:
  /**
   * @brief Construct a new Json Path object.
   *
   * @param jsonPath
   */
  explicit JsonPath(const std::string &jsonPath);
  /**
   * @brief Construct a new Json Path object.
   *
   * @param o
   */
  JsonPath(const JsonPath &o);
  /**
   * @brief Return iterator at the begining.
   *
   * @return vector<string>::const_iterator
   */
  std::vector<std::string>::const_iterator begin() const noexcept;
  /**
   * @brief Return iterator at the end.
   *
   * @return vector<string>::const_iterator
   */
  std::vector<std::string>::const_iterator end() const noexcept;
};

} // namespace builder::internals::utils

#endif // _UTILS_H

#include "utils.hpp"

#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace builder::internals::utils {

JsonPath::JsonPath(const string &jsonPath) {
  istringstream stream(jsonPath);
  char separator = '.';

  for (string subString; getline(stream, subString, separator);
       this->m_jsonPath.push_back(subString))
    ;
}
JsonPath::JsonPath(const JsonPath &o) : m_jsonPath{o.m_jsonPath} {}
vector<string>::const_iterator JsonPath::begin() const noexcept {
  return this->m_jsonPath.begin();
}
vector<string>::const_iterator JsonPath::end() const noexcept {
  return this->m_jsonPath.end();
}

} // namespace builder::internals::utils

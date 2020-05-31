#pragma once
#include <string>

class StringHelper {
  public:
  static bool replace_string(std::string& data, const std::string& to_search, const std::string& to_replace) {
    
    auto pos {data.find(to_search)};
    const auto ret_val { std::string::npos != pos };
    while (std::string::npos != pos) {
      data.replace(pos, to_search.size(), to_replace);
      pos = data.find(to_search, pos + to_replace.size());
    }
    return ret_val;
  }
};
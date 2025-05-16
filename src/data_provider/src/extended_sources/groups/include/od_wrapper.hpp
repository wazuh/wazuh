#pragma once

#include <map>
#include <string>


void genODEntries(const std::string& recordType,
                  const std::string* record,
                  std::map<std::string, bool>& names);

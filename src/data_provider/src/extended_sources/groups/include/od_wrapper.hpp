#pragma once

#include <map>
#include <string>

namespace od
{

    void genEntries(const std::string& record_type, const std::string* record, std::map<std::string, bool>& names);

} // namespace od

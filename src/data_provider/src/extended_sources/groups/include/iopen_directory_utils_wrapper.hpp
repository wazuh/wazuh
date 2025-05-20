#pragma once

#include <map>
#include <string>

class IODUtilsWrapper
{
    public:
        virtual ~IODUtilsWrapper() = default;
        virtual void genEntries(const std::string& recordType,
                                const std::string* record,
                                std::map<std::string, bool>& names) = 0;
};

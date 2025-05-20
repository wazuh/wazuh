#pragma once

#include "iopen_directory_utils_wrapper.hpp"
#include "od_wrapper.hpp"

class ODUtilsWrapper : public IODUtilsWrapper
{
    public:
        void genEntries(const std::string& recordType,
                        const std::string* record,
                        std::map<std::string, bool>& names) override
        {
            od::genEntries(recordType, record, names);
        }
};

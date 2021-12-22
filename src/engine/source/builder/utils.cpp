#include "utils.h"

#include <string>
#include <vector>
#include <sstream>


using namespace std;

namespace builder
{
    namespace utils
    {
        JsonPath::JsonPath(const string& json_path)
        {
            istringstream stream(json_path);
            char separator = '.';

            for (string sub_string; getline(stream, sub_string, separator); this->json_path.push_back(sub_string));
        }
        JsonPath::JsonPath(const JsonPath& o): json_path(o.json_path) {}
        vector<string>::const_iterator JsonPath::begin() const noexcept
        {
            return this->json_path.begin();
        }
        vector<string>::const_iterator JsonPath::end() const noexcept
        {
            return this->json_path.end();
        }


    }
}

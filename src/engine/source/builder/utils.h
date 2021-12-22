#pragma once
#include <string>
#include <vector>

using namespace std;

namespace builder
{
    /**
     * @brief defines helper classes and functions for builders.
     *
     */
    namespace utils
    {
        /**
         * @brief Represents a json path string.
         *
         * This class splits json path strings to its individual components.
         *
         */
        class JsonPath
        {
            public:
                /**
                 * @brief Construct a new Json Path object.
                 *
                 * @param json_path
                 */
                explicit JsonPath(const string& json_path);
                /**
                 * @brief Construct a new Json Path object.
                 *
                 * @param o
                 */
                JsonPath(const JsonPath& o);
                /**
                 * @brief Return iterator at the begining.
                 *
                 * @return vector<string>::const_iterator
                 */
                vector<string>::const_iterator begin() const noexcept;
                /**
                 * @brief Return iterator at the end.
                 *
                 * @return vector<string>::const_iterator
                 */
                vector<string>::const_iterator end() const noexcept;

            private:
                vector<string> json_path;
        };



    }
}

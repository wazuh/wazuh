#pragma once

#include <string>
#include <vector>


/**
 * @brief defines helper classes and functions for builders.
 *
 */
namespace builder::utils
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
            explicit JsonPath(const std::string& json_path);
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
            std::vector<std::string>::const_iterator begin() const noexcept;
            /**
             * @brief Return iterator at the end.
             *
             * @return vector<string>::const_iterator
             */
            std::vector<std::string>::const_iterator end() const noexcept;

        private:
            std::vector<std::string> json_path;
    };

}

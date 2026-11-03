#pragma once

#include <string>
#include <vector>

/// @brief Lines kept in the order they were added, each one at most once.
class UniqueLines
{
    public:
        /// @brief Appends a line unless an identical one is already held. Empty lines are ignored.
        void Add(const std::string& line);

        /// @brief Whether no line has been kept.
        bool Empty() const;

        /// @brief The kept lines, separated by '\n'.
        std::string Join() const;

    private:
        std::vector<std::string> m_lines;
};

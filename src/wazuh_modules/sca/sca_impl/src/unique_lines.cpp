#include <unique_lines.hpp>

#include <algorithm>

void UniqueLines::Add(const std::string& line)
{
    if (!line.empty() && std::find(m_lines.begin(), m_lines.end(), line) == m_lines.end())
    {
        m_lines.push_back(line);
    }
}

bool UniqueLines::Empty() const
{
    return m_lines.empty();
}

std::string UniqueLines::Join() const
{
    std::string joined;

    for (const auto& line : m_lines)
    {
        joined += (joined.empty() ? "" : "\n") + line;
    }

    return joined;
}

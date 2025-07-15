#include <kvdb/refCounter.hpp>

namespace kvdbManager
{

void RefCounter::addRef(const std::string& name, const uint32_t times)
{
    m_refMap[name] += times;
}

void RefCounter::removeRef(const std::string& name)
{
    auto it = m_refMap.find(name);
    if (it != m_refMap.end())
    {
        it->second--;
        if (0 == it->second)
        {
            m_refMap.erase(it);
        }
    }
}

uint32_t RefCounter::count(const std::string& name) const
{
    auto it = m_refMap.find(name);

    if (it != m_refMap.end())
    {
        return it->second;
    }

    return 0;
}

bool RefCounter::empty() const
{
    return m_refMap.empty();
}

std::vector<std::string> RefCounter::getRefNames() const
{
    std::vector<std::string> refNames;
    refNames.reserve(m_refMap.size());

    for (const auto& ref : m_refMap)
    {
        refNames.push_back(ref.first);
    }
    return refNames;
}

std::map<std::string, uint32_t> RefCounter::getRefMap() const
{
    return m_refMap;
}

} // namespace kvdbManager

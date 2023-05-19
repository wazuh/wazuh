#include <kvdb2/refCounter.hpp>

namespace kvdbManager
{

RefCounter::RefCounter(const RefCounter& other)
{
    m_refMap = other.m_refMap;
}

void RefCounter::addRef(const std::string& name)
{
    m_refMap[name]++;
}

void RefCounter::removeRef(const std::string& name)
{
    if (m_refMap.count(name) > 0)
    {
        m_refMap[name]--;
        if (m_refMap[name] == 0)
        {
            m_refMap.erase(name);
        }
    }
}

int RefCounter::count(const std::string& name) const
{
    if (m_refMap.count(name) > 0)
    {
        return m_refMap.at(name);
    }
    else
    {
        return 0;
    }
}

bool RefCounter::empty() const
{
    return m_refMap.empty();
}

std::vector<std::string> RefCounter::getRefNames() const
{
    std::vector<std::string> refNames;
    for (const auto& ref : m_refMap)
    {
        refNames.push_back(ref.first);
    }
    return refNames;
}

std::map<std::string, int> RefCounter::getRefMap() const
{
    return m_refMap;
}

} // namespace kvdbManager

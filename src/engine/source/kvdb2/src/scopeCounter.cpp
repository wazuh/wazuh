#include <kvdb2/scopeCounter.hpp>

namespace kvdbManager
{

void ScopeCounter::addScope(const std::string& name)
{
   scopeMap[name]++;
}

void ScopeCounter::removeScope(const std::string& name)
{
    if (scopeMap.count(name) > 0)
    {
        scopeMap[name]--;
        if (scopeMap[name] == 0)
        {
            scopeMap.erase(name);
        }
    }
}

int ScopeCounter::count(const std::string& name) const
{
    if (scopeMap.count(name) > 0)
    {
        return scopeMap.at(name);
    }
    else
    {
        return 0;
    }
}

bool ScopeCounter::empty() const
{
    return scopeMap.empty();
}

} // namespace kvdbManager

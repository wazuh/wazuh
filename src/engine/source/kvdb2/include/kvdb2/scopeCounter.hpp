#ifndef _SCOPECOUNTER_H
#define _SCOPECOUNTER_H

#include <string>
#include <map>

namespace kvdbManager
{

class ScopeCounter
{
public:
    void addScope(const std::string& name);
    void removeScope(const std::string& name);
    int count(const std::string& name) const;
    bool empty() const;
private:
    std::map<std::string, int> scopeMap;
};

} // namespace kvdbManager

#endif // _SCOPECOUNTER_H

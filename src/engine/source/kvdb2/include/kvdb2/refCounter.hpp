#ifndef _REFCOUNTER_H
#define _REFCOUNTER_H

#include <map>
#include <string>
#include <vector>

namespace kvdbManager
{

class RefCounter
{
public:
    RefCounter() = default;
    RefCounter(const RefCounter&);
    void addRef(const std::string& name);
    void removeRef(const std::string& name);
    int count(const std::string& name) const;
    bool empty() const;
    std::vector<std::string> getRefNames() const;
    std::map<std::string, int> getRefMap() const;
private:
    std::map<std::string, int> m_refMap;
};

} // namespace kvdbManager

#endif // _REFCOUNTER_H

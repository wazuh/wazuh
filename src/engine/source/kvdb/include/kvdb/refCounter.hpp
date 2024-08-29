#ifndef _KVDB_REF_COUNTER_H
#define _KVDB_REF_COUNTER_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace kvdbManager
{

/**
 * @brief Basic Helper wrapping std::map<std::string, uint32_t> to count references.
 *
 */
class RefCounter
{
public:
    /**
     * @brief Construct a new RefCounter object
     *
     */
    RefCounter() = default;

    /**
     * @brief Destroy the RefCounter object
     *
     */
    ~RefCounter() { m_refMap.clear(); }

    /**
     * @brief Add n reference(s) to the counter.
     *
     * @param name Reference name to increase
     * @param times How many times to increase the reference. Default is 1.
     */
    void addRef(const std::string& name, const uint32_t times = 1);

    /**
     * @brief Remove 1 reference from the counter.
     *
     * @param name Reference name to decrease
     */
    void removeRef(const std::string& name);

    /**
     * @brief Get the number of references for a given name.
     *
     * @param name Reference name to get the count.
     * @return uint32_t Number of references for the given name.
     */
    uint32_t count(const std::string& name) const;

    /**
     * @brief Checks if there are no references to any name.
     *
     * @return true If there are no references.
     */
    bool empty() const;

    /**
     * @brief Get the names of the references.
     *
     * @return std::vector<std::string> Names of the references.
     */
    std::vector<std::string> getRefNames() const;

    /**
     * @brief Get the map of references with the counters also.
     *
     * @return std::map<std::string, int> Map of references.
     */
    std::map<std::string, uint32_t> getRefMap() const;

private:
    /**
     * @brief Map of references with the counters.
     *
     */
    std::map<std::string, uint32_t> m_refMap;
};

} // namespace kvdbManager

#endif // _KVDB_REF_COUNTER_H

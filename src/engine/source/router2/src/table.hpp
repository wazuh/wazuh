#ifndef _ROUTER2_TABLE_HPP
#define _ROUTER2_TABLE_HPP

#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include <router/types.hpp>

#include "environment.hpp"

namespace router
{

// Table here
namespace internal
{
class RouteEntry : public Entry
{
private:
    std::shared_ptr<Environment> m_environment;

public:
    explicit RouteEntry(const Entry& entry)
        : Entry {entry} {
            // build environment
        };

    const std::shared_ptr<Environment>& environment() const { return m_environment; }

    bool available() const { return m_environment != nullptr && this->m_status == env::State::ACTIVE; }

    base::OptError build();

    const Entry& entry() const
    {
        // Update metada
        return *this;
    }
};

/**
 * @brief A template class to store and manage objects with unique names and priorities.
 *
 * @tparam T The type of object to be stored. T must have the following methods:
 * - std::size_t priority() const
 * - void priority(std::size_t)
 * - const std::string& name() const
 * - void name(const std::string&)
 *
 * The objects are stored in a set sorted by priority, and can be accessed by name
 * using a hash map for fast lookup.
 */
template<typename T>
class Table
{
private:
    /// Function to compare objects by priority.
    struct CompareByPriority
    {
        bool operator()(const T& lhs, const T& rhs) const { return lhs.priority() < rhs.priority(); }
    };

    /// Set to store the objects, sorted by priority.
    std::set<T, CompareByPriority> priorSet;

    /// Hash map to index the objects by name.
    std::unordered_map<std::string, typename std::set<T>::iterator> nameIndex;

public:
    // Check if T has a priority method that returns a std::size_t
    static_assert(std::is_same<decltype(std::declval<T>().priority()), std::size_t>::value,
                  "Type T must have a std::size_t priority() method");

    // Check if T has a priority method that accepts a std::size_t
    static_assert(std::is_same<decltype(std::declval<T>().priority(std::declval<std::size_t>())), void>::value,
                  "Type T must have a void priority(std::size_t) method");

    // Check if T has a name method that returns a const std::string&
    static_assert(std::is_same<decltype(std::declval<const T>().name()), const std::string&>::value,
                  "Type T must have a const std::string& name() const method");

    // Check if T has a name method that accepts a const std::string&
    static_assert(std::is_same<decltype(std::declval<T>().name(std::declval<const std::string&>())), void>::value,
                  "Type T must have a void name(const std::string&) method");

    /**
     * @brief Check if a priority is already used.
     *
     * @param priority The priority to check.
     * @return true if the priority is used, false otherwise.
     */
    bool priorityExists(std::size_t priority) const
    {
        return std::any_of(
            priorSet.begin(), priorSet.end(), [priority](const T& item) { return item.priority() == priority; });
    }

    /**
     * @brief Check if a name is already used.
     *
     * @param name The name to check.
     * @return true if the name is used, false otherwise.
     */
    bool nameExists(const std::string& name) const { return nameIndex.find(name) != nameIndex.end(); }

    /**
     * @brief Insert a new object.
     *
     * @param entry The object to insert.
     * @return true if the object was inserted, false if the name or priority is already used.
     */
    bool insert(T&& entry)
    {
        if (nameExists(entry.name()) || priorityExists(entry.priority()))
        {
            return false;
        }

        auto [it, inserted] = priorSet.insert(std::move(entry));
        if (!inserted)
        {
            return false;
        }
        nameIndex[it->name()] = it;
        return true;
    }

    /**
     * @brief Set a new priority for an object.
     *
     * @param name The name of the object.
     * @param newPriority The new priority.
     * @return true if the priority was updated, false if the name or priority is already used.
     */
    bool setPriority(const std::string& name, std::size_t newPriority)
    {
        auto name_it = nameIndex.find(name);
        if (name_it == nameIndex.end())
        {
            return false;
        }

        auto node_handler = priorSet.extract(name_it->second);
        if (node_handler.empty())
        {
            return false;
        }

        // Safely update the priority, while ensuring the set and map stay in sync
        node_handler.value().priority(newPriority); // Update priority
        auto insert_result = priorSet.insert(std::move(node_handler));
        if (!insert_result.inserted)
        {
            return false;
        }
        nameIndex[name] = insert_result.position;
        return true;
    }

    /**
     * @brief Get a reference to an object by name.
     *
     * @param name The name of the object.
     * @return A reference to the object.
     * @throw std::out_of_range if no object with the given name exists.
     */
    T& get(const std::string& name)
    {
        auto it = nameIndex.find(name);
        if (it == nameIndex.end())
        {
            throw std::out_of_range("No element with the given name.");
        }
        return *(it->second);
    }

    /**
     * @brief Get a const reference to an object by name.
     *
     * @param name The name of the object.
     * @return A const reference to the object.
     * @throw std::out_of_range if no object with the given name exists.
     */
    const T& get(const std::string& name) const
    {
        auto it = nameIndex.find(name);
        if (it == nameIndex.end())
        {
            throw std::out_of_range("No element with the given name.");
        }
        return *(it->second);
    }

    class iterator
    {
    private:
        typename std::set<T>::iterator it;

    public:
        iterator() = default; // Default constructor

        explicit iterator(typename std::set<T>::iterator it)
            : it(it)
        {
        }

        const T& operator*() const { return *it; }
        const T* operator->() const { return &(*it); } // Support pointer-like access

        // Prefix increment
        iterator& operator++()
        {
            ++it;
            return *this;
        }

        // Postfix increment
        iterator operator++(int)
        {
            iterator temp = *this;
            ++(*this);
            return temp;
        }

        bool operator==(const iterator& other) const { return it == other.it; }
        bool operator!=(const iterator& other) const { return it != other.it; }
    };

    class const_iterator
    {
    private:
        typename std::set<T>::const_iterator it;

    public:
        const_iterator() = default; // Default constructor

        explicit const_iterator(typename std::set<T>::const_iterator it)
            : it(it)
        {
        }

        const T& operator*() const { return *it; }
        const T* operator->() const { return &(*it); } // Support pointer-like access

        // Prefix increment
        const_iterator& operator++()
        {
            ++it;
            return *this;
        }

        // Postfix increment
        const_iterator operator++(int)
        {
            const_iterator temp = *this;
            ++(*this);
            return temp;
        }

        bool operator==(const const_iterator& other) const { return it == other.it; }
        bool operator!=(const const_iterator& other) const { return it != other.it; }
    };

    /**
     * @brief Get an iterator to the beginning of the set.
     *
     * @return An iterator to the beginning of the set.
     */
    iterator begin() { return iterator(priorSet.begin()); }

    /**
     * @brief Get an iterator to the end of the set.
     *
     * @return An iterator to the end of the set.
     */
    iterator end() { return iterator(priorSet.end()); }

    /**
     * @brief Get a const iterator to the beginning of the set.
     *
     * @return A const iterator to the beginning of the set.
     */
    const_iterator begin() const { return const_iterator(priorSet.cbegin()); }

    /**
     * @brief Get a const iterator to the end of the set.
     *
     * @return A const iterator to the end of the set.
     */
    const_iterator end() const { return const_iterator(priorSet.cend()); }

    /**
     * @brief Get a const iterator to the beginning of the set.
     *
     * @return A const iterator to the beginning of the set.
     */
    const_iterator cbegin() const { return const_iterator(priorSet.cbegin()); }

    /**
     * @brief Get a const iterator to the end of the set.
     *
     * @return A const iterator to the end of the set.
     */
    const_iterator cend() const { return const_iterator(priorSet.cend()); }

    /**
     * @brief Size of the set.
     *
     */
    std::size_t size() const { return priorSet.size(); }

    /**
     * @brief Check if the set is empty.
     *
     */
    bool empty() const { return priorSet.empty(); }

};
} // namespace interal

} // namespace router

#endif // _ROUTER2_TABLE_HPP

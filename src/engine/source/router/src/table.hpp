#ifndef _ROUTER_TABLE_HPP
#define _ROUTER_TABLE_HPP

#include <list>
#include <memory>
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
/**
 * @brief A template class to store and manage objects with unique names and priorities.
 *
 * @tparam T The type of object to be stored. Must be move constructible.
 *
 * The objects are stored in a set sorted by priority, and can be accessed by name
 * using a hash map for fast lookup.
 */
template<typename T>
class Table
{
private:
    // Struct to hold the object along with its name and priority
    struct Item
    {
        std::string name;
        std::size_t priority;
        T object;

        Item(std::string n, std::size_t p, T obj)
            : name(std::move(n))
            , priority(p)
            , object(std::move(obj))
        {
        }
    };

    // List to store the items, sorted by priority if needed.
    std::list<Item> m_itemList;

    // Hash map to index the items by name.
    std::unordered_map<std::string, typename std::list<Item>::iterator> m_nameIndex;

    // Function to find the insertion point based on priority.
    typename std::list<Item>::iterator findInsertionPoint(std::size_t priority)
    {
        return std::find_if(
            m_itemList.begin(), m_itemList.end(), [priority](const Item& item) { return item.priority >= priority; });
    }

public:
    /**
     * @brief Default constructor.
     */
    Table() = default;

    /**
     * @brief Check if a priority is already used.
     *
     * @param priority The priority to check.
     * @return true if the priority is used, false otherwise.
     */
    bool priorityExists(std::size_t priority) const
    {
        for (const auto& item : m_itemList)
        {
            if (item.priority == priority)
                return true;
            if (item.priority > priority)
                break;
        }
        return false;
    }

    /**
     * @brief Check if a name is already used.
     *
     * @param name The name to check.
     * @return true if the name is used, false otherwise.
     */
    bool nameExists(const std::string& name) const { return m_nameIndex.find(name) != m_nameIndex.end(); }

    /**
     * @brief Insert a new object with name and priority.
     *
     * @param name The name of the object.
     * @param priority The priority of the object.
     * @param object The object to insert.
     * @return true if the object was inserted, false if the name or priority is already used.
     */
    bool insert(const std::string& name, std::size_t priority, T&& object)
    {
        // Check if name or priority already exists
        if (nameExists(name) || priorityExists(priority))
        {
            return false;
        }

        auto it = findInsertionPoint(priority);
        auto emplacedItem = m_itemList.emplace(it, Item(name, priority, std::move(object)));
        m_nameIndex[name] = emplacedItem;
        return true;
    }

    /**
     * @brief Insert a new object with name and priority.
     *
     * @param name The name of the object.
     * @param priority The priority of the object.
     * @param object The object to insert.
     * @return true if the object was inserted, false if the name or priority is already used.
     */
    bool insert(const std::string& name, std::size_t priority, const T& object)
    {
        // Check if name or priority already exists
        if (nameExists(name) || priorityExists(priority))
        {
            return false;
        }

        auto it = findInsertionPoint(priority);
        auto emplacedItem = m_itemList.emplace(it, Item(name, priority, object));
        m_nameIndex[name] = emplacedItem;
        return true;
    }

    /**
     * @brief Delete an object by name.
     * @param name The name of the object.
     * @return true if the object was deleted, false if the name does not exist.
     */
    bool erase(const std::string& name)
    {
        auto it = m_nameIndex.find(name);
        if (it != m_nameIndex.end())
        {
            m_itemList.erase(it->second);
            m_nameIndex.erase(it);
            return true;
        }
        return false;
    }

    /**
     * @brief Set a new priority for an object.
     *
     * @param name The name of the object.
     * @param newPriority The new priority.
     * @return true if the priority was updated or the priority is the same, false if the name does not exist or the new
     * priority is already used.
     */
    bool setPriority(const std::string& name, std::size_t newPriority)
    {
        auto name_it = m_nameIndex.find(name);
        if (name_it == m_nameIndex.end())
        {
            return false; // Name does not exist
        }

        if (name_it->second->priority == newPriority)
        {
            return true; // New priority is the same
        }
        if (priorityExists(newPriority))
        {
            return false; // New priority is already used
        }

        // Create a new Item object with the new priority
        auto item_it = name_it->second;
        Item newItem(item_it->name, newPriority, std::move(item_it->object));

        // Erase the old item and update the index
        m_itemList.erase(item_it);
        m_nameIndex.erase(name_it);

        // Insert the new item and update the index
        auto new_it = findInsertionPoint(newPriority);
        auto emplacedItem = m_itemList.emplace(new_it, std::move(newItem));
        m_nameIndex[name] = emplacedItem;

        return true;
    }

    /**
     * @brief Get the biggest free priority in range [minPriority, maxPriority].
     *
     * @param minPriority The minimum priority to check.
     * @param maxPriority The maximum priority to check.
     * @return std::size_t The lowest free priority.
     * @throw std::out_of_range if there is no free priority in the range.
     */
    std::size_t getBiggestFreePriority(std::size_t minPriority, std::size_t maxPriority) const
    {
        if (minPriority < maxPriority)
        {
            throw std::runtime_error {"The lowest priority cannot be lower than the highest priority."};
        }

        for (std::size_t priority = maxPriority; priority <= minPriority; priority++)
        {
            if (priorityExists(priority))
            {
                continue;
            }

            // Return the lowest free priority found
            return priority;
        }

        // No free priority found in the specified range
        throw std::out_of_range("No free priority in the specified range.");
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
        auto it = m_nameIndex.find(name);
        if (it == m_nameIndex.end())
        {
            throw std::out_of_range("No element with the given name.");
        }
        // Return a reference to the object of type T within the Item struct.
        return it->second->object;
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
        auto it = m_nameIndex.find(name);
        if (it == m_nameIndex.end())
        {
            throw std::out_of_range("No element with the given name.");
        }
        // Return a reference to the object of type T within the Item struct.
        return it->second->object;
    }

    class iterator
    {
        typename std::list<Item>::iterator it;

    public:
        iterator(typename std::list<Item>::iterator it)
            : it(it)
        {
        }

        T& operator*() { return it->object; }
        T* operator->() { return &(it->object); }

        iterator& operator++()
        {
            ++it;
            return *this;
        }

        iterator operator++(int)
        {
            iterator tmp = *this;
            ++(*this);
            return tmp;
        }

        bool operator==(const iterator& other) const { return it == other.it; }
        bool operator!=(const iterator& other) const { return it != other.it; }
    };

    class const_iterator
    {
    private:
        typename std::list<Item>::const_iterator it;

    public:
        const_iterator() = default;

        explicit const_iterator(typename std::list<Item>::const_iterator it)
            : it(it)
        {
        }

        const T& operator*() const { return it->object; }
        const T* operator->() const { return &(it->object); }

        const_iterator& operator++()
        {
            ++it;
            return *this;
        }

        const_iterator operator++(int)
        {
            const_iterator tmp = *this;
            ++(*this);
            return tmp;
        }

        bool operator==(const const_iterator& other) const { return it == other.it; }
        bool operator!=(const const_iterator& other) const { return it != other.it; }
    };

    /**
     * @brief Get an iterator to the beginning of the set.
     *
     * @return An iterator to the beginning of the set.
     */
    iterator begin() { return iterator(m_itemList.begin()); }

    /**
     * @brief Get an iterator to the end of the set.
     *
     * @return An iterator to the end of the set.
     */
    iterator end() { return iterator(m_itemList.end()); }

    /**
     * @brief Get a const iterator to the beginning of the set.
     *
     * @return A const iterator to the beginning of the set.
     */
    const_iterator begin() const { return const_iterator(m_itemList.cbegin()); }

    /**
     * @brief Get a const iterator to the end of the set.
     *
     * @return A const iterator to the end of the set.
     */
    const_iterator end() const { return const_iterator(m_itemList.cend()); }

    /**
     * @brief Get a const iterator to the beginning of the set.
     *
     * @return A const iterator to the beginning of the set.
     */
    const_iterator cbegin() const { return const_iterator(m_itemList.cbegin()); }

    /**
     * @brief Get a const iterator to the end of the set.
     *
     * @return A const iterator to the end of the set.
     */
    const_iterator cend() const { return const_iterator(m_itemList.cend()); }

    /**
     * @brief Size of the set.
     *
     */
    std::size_t size() const { return m_itemList.size(); }

    /**
     * @brief Check if the set is empty.
     *
     */
    bool empty() const { return m_itemList.empty(); }

    /**
     * @brief Get list of all names and priorities.
     *
     */
    std::vector<std::pair<std::string, std::size_t>> list() const
    {
        std::vector<std::pair<std::string, std::size_t>> result;
        result.reserve(m_itemList.size());
        for (const auto& item : m_itemList)
        {
            result.emplace_back(item.name, item.priority);
        }
        return result;
    }
};
} // namespace internal

} // namespace router

#endif // _ROUTER_TABLE_HPP

#include <gtest/gtest.h>

#include <tuple>
#include <utility>
#include <vector>

#include "table.hpp"

namespace ri = router::internal;

/**
 * @brief A class to test the Table class
 */
class EntryTest
{
private:
    std::string m_name;
    std::size_t m_priority;

public:
    EntryTest(std::string name, std::size_t priority)
        : m_name {std::move(name)}
        , m_priority {priority}
    {
    }

    std::size_t priority() const { return m_priority; }
    void priority(std::size_t priority) { m_priority = priority; }
    const std::string& name() const { return m_name; }
    void name(const std::string& name) { m_name = name; }
};

/**
 * @brief Check if the entry is in the table.
 *
 * @param table The table to check.
 * @param entry The entry to check.
 * @param inserted true if the entry should be in the table, false otherwise.
 */
void checkEntryTable(const ri::Table<EntryTest>& table, const EntryTest& entry, bool inserted)
{
    if (inserted)
    {
        // Check if the name and priority exists
        EXPECT_TRUE(table.nameExists(entry.name()));
        EXPECT_TRUE(table.priorityExists(entry.priority()));

        // Check if the name and the priority is the same entry
        const auto& entryTable = table.get(entry.name());
        EXPECT_EQ(entryTable.name(), entry.name());
        EXPECT_EQ(entryTable.priority(), entry.priority());
    }
    else
    {
        // Insert only fails if the name or the priority is already used
        bool res = table.nameExists(entry.name()) || table.priorityExists(entry.priority());
        EXPECT_TRUE(res);
    }
}

/************************************************
 *          Test the insert/get method.
 ************************************************/
using InsertT = std::vector<std::pair<EntryTest, bool>>;
using InsertTest = ::testing::TestWithParam<InsertT>;

class EasyInsert
{
private:
    InsertT m_insert;

public:
    EasyInsert() = default;

    EasyInsert& add(std::string name, std::size_t priority, bool expected)
    {
        m_insert.push_back({{std::move(name), priority}, expected});
        return *this;
    }

    // Cast EasyInsert to InsertT
    operator InsertT() const { return m_insert; }
};

TEST_P(InsertTest, Insert)
{
    auto& arrayTest = GetParam();
    ri::Table<EntryTest> table;
    for (auto& [entry, expected] : arrayTest)
    {
        EXPECT_EQ(table.insert(EntryTest(entry)), expected);
        checkEntryTable(table, entry, expected);
    }
}

INSTANTIATE_TEST_SUITE_P(Table,
                         InsertTest,
                         ::testing::Values(
                             // Test to insert by name
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 3, true),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("a", 3, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("b", 3, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("a", 2, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("b", 1, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 1, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 1, false).add("c", 3, true),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 2, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("b", 3, false).add("c", 3, true)
                             // end
                             ));

/************************************************
 *      Test the order iterator by priority.
 ************************************************/

using ItByPriorityT = std::vector<EntryTest>;
using ItTest = ::testing::TestWithParam<ItByPriorityT>;

class EasyIt
{
private:
    ItByPriorityT m_arrayEntry;

public:
    EasyIt() = default;

    EasyIt& add(std::string name, std::size_t priority)
    {
        m_arrayEntry.push_back({std::move(name), priority});
        return *this;
    }

    // Cast EasyIt to ItByPriorityT
    operator ItByPriorityT() const { return m_arrayEntry; }
};

TEST_P(ItTest, It)
{
    auto& arrayTest = GetParam();
    ri::Table<EntryTest> table;
    // Insert all entries (And check if the insert is ok)
    for (auto& entry : arrayTest)
    {
        ASSERT_TRUE(table.insert(EntryTest(entry)));
        checkEntryTable(table, entry, true);
    }

    ASSERT_TRUE(table.size() == arrayTest.size());
    ASSERT_FALSE(table.empty());

    // Check if the iterator return the entries in the right order (Higher priority first)
    std::size_t lastPriority = 0;

    // Check reference
    for (auto& entry : table)
    {
        EXPECT_GE(entry.priority(), lastPriority);
        lastPriority = entry.priority();
    }

    // Check const reference
    lastPriority = 0;
    for (const auto& entry : table)
    {
        EXPECT_GE(entry.priority(), lastPriority);
        lastPriority = entry.priority();
    }

    // Check iterator
    lastPriority = 0;
    for (auto it = table.begin(); it != table.end(); ++it)
    {
        EXPECT_GE(it->priority(), lastPriority);
        lastPriority = it->priority();
    }

    // Check const iterator
    lastPriority = 0;
    for (auto it = table.cbegin(); it != table.cend(); ++it)
    {
        EXPECT_GE(it->priority(), lastPriority);
        lastPriority = it->priority();
    }
}

INSTANTIATE_TEST_SUITE_P(Table,
                         ItTest,
                         ::testing::Values(
                             // Test to insert by name
                             EasyIt().add("a", 1).add("b", 2).add("c", 3),
                             EasyIt().add("a", 3).add("b", 2).add("c", 1),
                             EasyIt().add("a", 1).add("b", 3).add("c", 2),
                             EasyIt().add("a", 3).add("b", 1).add("c", 2),
                             EasyIt().add("a", 2).add("b", 1).add("c", 3),
                             EasyIt().add("a", 2).add("b", 3).add("c", 1),
                             EasyIt().add("a", 1).add("b", 2).add("c", 3).add("d", 4),
                             EasyIt().add("a", 1).add("b", 2).add("c", 3).add("d", 4).add("e", 5),
                             EasyIt().add("a", 1).add("b", 2).add("c", 3).add("d", 4).add("e", 5).add("f", 6),
                             EasyIt().add("a", 6).add("b", 5).add("c", 4).add("d", 3).add("e", 2).add("f", 1),
                             EasyIt().add("a", 5).add("b", 44).add("c", 33).add("d", 55).add("e", 110).add("f", 90)
                             // end
                             ));
